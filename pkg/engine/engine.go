package engine

import (
	"bytes"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"os"
	"fmt"

	"hash/fnv"
	"io/ioutil"


	"github.com/sirupsen/logrus"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/decoders"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

type Engine struct {
	concurrency     int
	chunks          chan *sources.Chunk
	results         chan detectors.ResultWithMetadata
	decoders        []decoders.Decoder
	detectors       map[bool][]detectors.Detector
	chunksScanned   uint64
	bytesScanned    uint64
	detectorAvgTime sync.Map
	sourcesWg       sync.WaitGroup
	workersWg       sync.WaitGroup
	// filterUnverified is used to reduce the number of unverified results.
	// If there are multiple unverified results for the same chunk for the same detector,
	// only the first one will be kept.
	filterUnverified bool
}

type EngineOption func(*Engine)

func WithConcurrency(concurrency int) EngineOption {
	return func(e *Engine) {
		e.concurrency = concurrency
	}
}

func WithDetectors(verify bool, d ...detectors.Detector) EngineOption {
	return func(e *Engine) {
		if e.detectors == nil {
			e.detectors = make(map[bool][]detectors.Detector)
		}
		if e.detectors[verify] == nil {
			e.detectors[true] = []detectors.Detector{}
			e.detectors[false] = []detectors.Detector{}
		}
		e.detectors[verify] = append(e.detectors[verify], d...)
	}
}

func WithDecoders(decoders ...decoders.Decoder) EngineOption {
	return func(e *Engine) {
		e.decoders = decoders
	}
}

// WithFilterUnverified sets the filterUnverified flag on the engine. If set to
// true, the engine will only return the first unverified result for a chunk for a detector.
func WithFilterUnverified(filter bool) EngineOption {
	return func(e *Engine) {
		e.filterUnverified = filter
	}
}

func Start(ctx context.Context, options ...EngineOption) *Engine {
	e := &Engine{
		chunks:          make(chan *sources.Chunk),
		results:         make(chan detectors.ResultWithMetadata),
		detectorAvgTime: sync.Map{},
	}

	for _, option := range options {
		option(e)
	}

	// Set defaults.

	if e.concurrency == 0 {
		numCPU := runtime.NumCPU()
		logrus.Warn("No concurrency specified, defaulting to ", numCPU)
		e.concurrency = numCPU
	}
	logrus.Debugf("running with up to %d workers", e.concurrency)

	if len(e.decoders) == 0 {
		e.decoders = decoders.DefaultDecoders()
	}

	if len(e.detectors) == 0 {
		e.detectors = map[bool][]detectors.Detector{}
		e.detectors[true] = DefaultDetectors()
		e.detectors[false] = []detectors.Detector{}
	}

	logrus.Debugf("loaded %d decoders", len(e.decoders))
	logrus.Debugf("loaded %d detectors total, %d with verification enabled. %d with verification disabled",
		len(e.detectors[true])+len(e.detectors[false]),
		len(e.detectors[true]),
		len(e.detectors[false]))

	// start the workers
	for i := 0; i < e.concurrency; i++ {
		e.workersWg.Add(1)
		go func() {
			defer common.RecoverWithExit(ctx)
			defer e.workersWg.Done()
			e.detectorWorker(ctx)
		}()
	}

	return e
}

// Finish waits for running sources to complete and workers to finish scanning
// chunks before closing their respective channels. Once Finish is called, no
// more sources may be scanned by the engine.
func (e *Engine) Finish(ctx context.Context) {
	defer common.RecoverWithExit(ctx)
	// wait for the sources to finish putting chunks onto the chunks channel
	e.sourcesWg.Wait()
	close(e.chunks)
	// wait for the workers to finish processing all of the chunks and putting
	// results onto the results channel
	e.workersWg.Wait()

	// TODO: re-evaluate whether this is needed and investigate why if so
	//
	// not entirely sure why results don't get processed without this pause
	// since we've put all results on the channel at this point.
	time.Sleep(time.Second)
	close(e.results)
}

func (e *Engine) ChunksChan() chan *sources.Chunk {
	return e.chunks
}

func (e *Engine) ResultsChan() chan detectors.ResultWithMetadata {
	return e.results
}

func (e *Engine) ChunksScanned() uint64 {
	return e.chunksScanned
}

func (e *Engine) BytesScanned() uint64 {
	return e.bytesScanned
}

func (e *Engine) DetectorAvgTime() map[string][]time.Duration {
	avgTime := map[string][]time.Duration{}
	e.detectorAvgTime.Range(func(k, v interface{}) bool {
		key, ok := k.(string)
		if !ok {
			logrus.Warnf("expected DetectorAvgTime key to be a string")
			return true
		}

		value, ok := v.([]time.Duration)
		if !ok {
			logrus.Warnf("expected DetectorAvgTime value to be []time.Duration")
			return true
		}
		avgTime[key] = value
		return true
	})
	return avgTime
}


func appendTextToFile(filename string, text string) {
	// Open the file in append mode
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
	  panic(err)
	}
	defer file.Close()
  
	// Append the text to the end of the file
	if _, err := file.WriteString(text); err != nil {
	  panic(err)
	}
  }

func hash(s string) string {
	h := fnv.New32a()
	h.Write([]byte(s))
	return string(h.Sum32())
}

func checkTextInFile(text string) bool {
	// Take the SHA256 hash of the input string
	hashString := hash(text)
	filename := "cache_th/" + hashString + "_cache.txt"
	checkOrCreateFile(text, filename)
	// Open the file with the given filename
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		panic(err)
	}

	// Check if the text appears in the file
	if strings.Contains(string(data), text) {
		return true
	} else {
		appendTextToFile(filename, text)
		return false
	}
}

func checkOrCreateFile(input string, filename string) {
	
  
	// Check if a file with the name of the hash exists
	_, err := os.Stat(filename)
	if os.IsNotExist(err) {
	  // Create the file if it does not exist
	  file, err := os.Create(filename)
	  if err != nil {
		panic(err)
	  }
	  defer file.Close()
	}
  }
  

func (e *Engine) detectorWorker(ctx context.Context) {
	for originalChunk := range e.chunks {
		for chunk := range sources.Chunker(originalChunk) {
			atomic.AddUint64(&e.bytesScanned, uint64(len(chunk.Data)))
			fragStart, mdLine := FragmentFirstLine(chunk)
			for _, decoder := range e.decoders {
				var decoderType detectorspb.DecoderType
				switch decoder.(type) {
				case *decoders.UTF8:
					decoderType = detectorspb.DecoderType_PLAIN
				case *decoders.Base64:
					decoderType = detectorspb.DecoderType_BASE64
				default:
					logrus.Warnf("unknown decoder type: %T", decoder)
					decoderType = detectorspb.DecoderType_UNKNOWN
				}
				decoded := decoder.FromChunk(chunk)
				if decoded == nil {
					continue
				}
				dataLower := strings.ToLower(string(decoded.Data))
				for verify, detectorsSet := range e.detectors {
					for _, detector := range detectorsSet {
						start := time.Now()
						foundKeyword := false
						for _, kw := range detector.Keywords() {
							if strings.Contains(dataLower, strings.ToLower(kw)) {
								foundKeyword = true
								break
							}
						}
						if !foundKeyword {
							continue
						}
						// log.Warn(ctx)
						results, err := func() ([]detectors.Result, error) {
							ctx, cancel := context.WithTimeout(ctx, time.Second*10)
							defer cancel()
							defer common.Recover(ctx)
							return detector.FromData(ctx, false, decoded.Data)
						}()
						if err != nil {
							logrus.WithFields(logrus.Fields{
								"source_type": decoded.SourceType.String(),
								"metadata":    decoded.SourceMetadata,
							}).WithError(err).Error("could not scan chunk")
							continue
						}

						key := fmt.Sprint(results)

						if !checkTextInFile(key) {
						
							// log.Warn(ctx)
							results, err := func() ([]detectors.Result, error) {
								ctx, cancel := context.WithTimeout(ctx, time.Second*10)
								defer cancel()
								defer common.Recover(ctx)
								return detector.FromData(ctx, verify, decoded.Data)
							}()
							if err != nil {
								logrus.WithFields(logrus.Fields{
									"source_type": decoded.SourceType.String(),
									"metadata":    decoded.SourceMetadata,
								}).WithError(err).Error("could not scan chunk")
								continue
							}
	
							
							if true {
								if e.filterUnverified {
									results = detectors.CleanResults(results)
								}
								for _, result := range results {
									SetResultLineNumber(chunk, &result, fragStart, mdLine)
									result.DecoderType = decoderType
									e.results <- detectors.CopyMetadata(chunk, result)
		
								}
								if len(results) > 0 {
									elapsed := time.Since(start)
									detectorName := results[0].DetectorType.String()
									avgTimeI, ok := e.detectorAvgTime.Load(detectorName)
									var avgTime []time.Duration
									if ok {
										avgTime, ok = avgTimeI.([]time.Duration)
										if !ok {
											continue
										}
									}
									avgTime = append(avgTime, elapsed)
									e.detectorAvgTime.Store(detectorName, avgTime)
								}
							}
						}
						
						
					}
				}
			}
		}
		atomic.AddUint64(&e.chunksScanned, 1)
	}
}

// gitSources is a list of sources that utilize the Git source. It is stored this way because slice consts are not
// supported.
func gitSources() []sourcespb.SourceType {
	return []sourcespb.SourceType{
		sourcespb.SourceType_SOURCE_TYPE_GIT,
		sourcespb.SourceType_SOURCE_TYPE_GITHUB,
		sourcespb.SourceType_SOURCE_TYPE_GITLAB,
		sourcespb.SourceType_SOURCE_TYPE_BITBUCKET,
		sourcespb.SourceType_SOURCE_TYPE_GERRIT,
		sourcespb.SourceType_SOURCE_TYPE_GITHUB_UNAUTHENTICATED_ORG,
		sourcespb.SourceType_SOURCE_TYPE_PUBLIC_GIT,
	}
}

func isGitSource(sourceType sourcespb.SourceType) bool {
	for _, i := range gitSources() {
		if i == sourceType {
			return true
		}
	}
	return false
}

// FragmentLineOffset sets the line number for a provided source chunk with a given detector result.
func FragmentLineOffset(chunk *sources.Chunk, result *detectors.Result) int64 {
	lines := bytes.Split(chunk.Data, []byte("\n"))
	for i, line := range lines {
		if bytes.Contains(line, result.Raw) {
			return int64(i)
		}
	}
	return 0
}

// FragmentFirstLine returns the first line number of a fragment along with a pointer to the value to update in the
// chunk metadata.
func FragmentFirstLine(chunk *sources.Chunk) (int64, *int64) {
	var fragmentStart *int64
	switch metadata := chunk.SourceMetadata.GetData().(type) {
	case *source_metadatapb.MetaData_Git:
		fragmentStart = &metadata.Git.Line
	case *source_metadatapb.MetaData_Github:
		fragmentStart = &metadata.Github.Line
	case *source_metadatapb.MetaData_Gitlab:
		fragmentStart = &metadata.Gitlab.Line
	case *source_metadatapb.MetaData_Bitbucket:
		fragmentStart = &metadata.Bitbucket.Line
	case *source_metadatapb.MetaData_Gerrit:
		fragmentStart = &metadata.Gerrit.Line
	default:
		return 0, nil
	}
	return *fragmentStart, fragmentStart
}

// SetResultLineNumber sets the line number in the provided result.
func SetResultLineNumber(chunk *sources.Chunk, result *detectors.Result, fragStart int64, mdLine *int64) {
	if isGitSource(chunk.SourceType) {
		offset := FragmentLineOffset(chunk, result)
		*mdLine = fragStart + offset
	}
}
