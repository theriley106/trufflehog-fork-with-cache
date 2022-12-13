package filesystem

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"hash/fnv"
	"io/ioutil"
	"strings"

	diskbufferreader "github.com/bill-rich/disk-buffer-reader"
	"github.com/go-errors/errors"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/handlers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sanitizer"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

const (
	// These buffer sizes are mainly driven by our largest credential size, which is GCP @ ~2.25KB.
	// Having a peek size larger than that ensures that we have complete credential coverage in our chunks.
	BufferSize = 10 * 1024 // 10KB
	PeekSize   = 3 * 1024  // 3KB
)

type Source struct {
	name     string
	sourceId int64
	jobId    int64
	verify   bool
	paths    []string
	aCtx     context.Context
	log      *log.Entry
	sources.Progress
}

// Ensure the Source satisfies the interface at compile time
var _ sources.Source = (*Source)(nil)

// Type returns the type of source.
// It is used for matching source types in configuration and job input.
func (s *Source) Type() sourcespb.SourceType {
	return sourcespb.SourceType_SOURCE_TYPE_FILESYSTEM
}

func (s *Source) SourceID() int64 {
	return s.sourceId
}

func (s *Source) JobID() int64 {
	return s.jobId
}

// Init returns an initialized Filesystem source.
func (s *Source) Init(aCtx context.Context, name string, jobId, sourceId int64, verify bool, connection *anypb.Any, _ int) error {
	s.log = log.WithField("source", s.Type()).WithField("name", name)

	s.aCtx = aCtx
	s.name = name
	s.sourceId = sourceId
	s.jobId = jobId
	s.verify = verify

	var conn sourcespb.Filesystem
	if err := anypb.UnmarshalTo(connection, &conn, proto.UnmarshalOptions{}); err != nil {
		return errors.WrapPrefix(err, "error unmarshalling connection", 0)
	}

	s.paths = conn.Directories

	return nil
}

func createCacheFolder() {
	// Check if the "cache" folder exists
	_, err := os.Stat("cache_th")
	if os.IsNotExist(err) {
	  // Create the "cache" folder if it does not exist
	  err = os.Mkdir("cache_th", os.ModePerm)
	  if err != nil {
		panic(err)
	  }
	}
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
	return fmt.Sprintf("%x", h.Sum32())
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
	  createCacheFolder()
	  // Create the file if it does not exist
	  file, err := os.Create(filename)
	  if err != nil {
		panic(err)
	  }
	  defer file.Close()
	}
  }
  



// Chunks emits chunks of bytes over a channel.
func (s *Source) Chunks(ctx context.Context, chunksChan chan *sources.Chunk) error {
	for i, path := range s.paths {
		s.SetProgressComplete(i, len(s.paths), fmt.Sprintf("Path: %s", path), "")

		cleanPath := filepath.Clean(path)
		done := false
		go func() {
			<-ctx.Done()
			done = true
		}()

		err := fs.WalkDir(os.DirFS(cleanPath), ".", func(relativePath string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}

			path := filepath.Join(cleanPath, relativePath)
			if checkTextInFile(path){
				log.Warn("Skipping" + path)
				return nil
			} else {

				fileStat, err := os.Stat(path)
				if err != nil {
					log.WithError(err).Warnf("unable to stat file: %s", path)
					return nil
				}
				if !fileStat.Mode().IsRegular() {
					return nil
				}

				inputFile, err := os.Open(path)
				if err != nil {
					log.Warn(err)
					return nil
				}
				defer inputFile.Close()
				log.WithField("file_path", path).Trace("scanning file")

				reReader, err := diskbufferreader.New(inputFile)
				if err != nil {
					log.WithError(err).Error("Could not create re-readable reader.")
				}
				defer reReader.Close()

				chunkSkel := &sources.Chunk{
					SourceType: s.Type(),
					SourceName: s.name,
					SourceID:   s.SourceID(),
					SourceMetadata: &source_metadatapb.MetaData{
						Data: &source_metadatapb.MetaData_Filesystem{
							Filesystem: &source_metadatapb.Filesystem{
								File: sanitizer.UTF8(path),
							},
						},
					},
					Verify: s.verify,
				}
				if handlers.HandleFile(ctx, reReader, chunkSkel, chunksChan) {
					return nil
				}

				if err := reReader.Reset(); err != nil {
					return err
				}
				reReader.Stop()
				data, err := io.ReadAll(reReader)
				if err != nil {
					return err
				}
				chunksChan <- &sources.Chunk{
					SourceType: s.Type(),
					SourceName: s.name,
					SourceID:   s.SourceID(),
					Data:       data,
					SourceMetadata: &source_metadatapb.MetaData{
						Data: &source_metadatapb.MetaData_Filesystem{
							Filesystem: &source_metadatapb.Filesystem{
								File: sanitizer.UTF8(path),
							},
						},
					},
					Verify: s.verify,
				}
				return nil
			}
			
		})

		if err != nil && err != io.EOF {
			return errors.New(err)
		}

		if done {
			return nil
		}

	}
	return nil
}
