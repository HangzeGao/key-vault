// Command flight-manual-header keeps the manual's public header reference exact.
package main

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	headerPath   = "embedded/tc_security/include/tc_security.h"
	markdownPath = "docs/FLIGHT_INTERFACE_MANUAL.md"
	wordPath     = "docs/星务端密码模块接口手册.docx"
	beginMarker  = "<!-- flight-public-header:begin -->"
	endMarker    = "<!-- flight-public-header:end -->"
)

func main() {
	check := flag.Bool("check", false, "check Markdown and Word against the current public header")
	sync := flag.Bool("sync", false, "update the Markdown header appendix before regenerating Word")
	root := flag.String("root", ".", "repository root")
	flag.Parse()
	if *check == *sync || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "choose exactly one of --sync or --check")
		os.Exit(2)
	}
	if err := run(*root, *sync); err != nil {
		fmt.Fprintln(os.Stderr, "flight manual header:", err)
		os.Exit(1)
	}
}

func normalize(value []byte) string { return strings.ReplaceAll(string(value), "\r\n", "\n") }

func readHeader(root string) (string, error) {
	data, err := os.ReadFile(filepath.Join(root, headerPath))
	if err != nil {
		return "", err
	}
	header := normalize(data)
	if !strings.HasPrefix(header, "#ifndef TC_SECURITY_H\n") || !strings.HasSuffix(header, "\n") {
		return "", errors.New("public header must have its include guard and a final newline")
	}
	return header, nil
}

func referenceBlock(header string) string {
	return beginMarker + "\n```c\n" + header + "```\n" + endMarker
}

func replaceReference(markdown, header string) (string, error) {
	begin, end := strings.Index(markdown, beginMarker), strings.Index(markdown, endMarker)
	if begin == -1 && end == -1 {
		if strings.Contains(markdown, "## 附录 C 对外头文件") {
			return "", errors.New("public-header appendix exists without its synchronization markers")
		}
		return strings.TrimRight(markdown, "\n") + "\n\n## 附录 C 对外头文件\n\n" +
			"本附录逐字引用 `embedded/tc_security/include/tc_security.h`，与静态库按同一接口版本发布。\n\n" + referenceBlock(header) + "\n", nil
	}
	if strings.Count(markdown, beginMarker) != 1 || strings.Count(markdown, endMarker) != 1 || end < begin {
		return "", errors.New("missing, duplicated or reversed public-header appendix markers")
	}
	return markdown[:begin] + referenceBlock(header) + markdown[end+len(endMarker):], nil
}

func checkMarkdown(markdown, header string) error {
	if strings.Count(markdown, beginMarker) != 1 || strings.Count(markdown, endMarker) != 1 ||
		!strings.Contains(markdown, referenceBlock(header)) {
		return errors.New("Markdown header appendix is stale; run go run ./scripts/tools/flight-manual-header --sync")
	}
	return nil
}

func wordParagraphs(reader io.Reader) ([]string, error) {
	decoder := xml.NewDecoder(reader)
	var paragraphs []string
	var paragraph strings.Builder
	inParagraph, inText := false, false
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			return paragraphs, nil
		}
		if err != nil {
			return nil, err
		}
		switch value := token.(type) {
		case xml.StartElement:
			switch value.Name.Local {
			case "p":
				paragraph.Reset()
				inParagraph = true
			case "t":
				inText = inParagraph
			case "br", "cr":
				if inParagraph {
					paragraph.WriteByte('\n')
				}
			case "tab":
				if inParagraph {
					paragraph.WriteByte('\t')
				}
			}
		case xml.EndElement:
			if value.Name.Local == "t" {
				inText = false
			}
			if value.Name.Local == "p" {
				paragraphs = append(paragraphs, paragraph.String())
				inParagraph, inText = false, false
			}
		case xml.CharData:
			if inText {
				paragraph.Write(value)
			}
		}
	}
}

func checkWord(path, header string) error {
	archive, err := zip.OpenReader(path)
	if err != nil {
		return err
	}
	defer archive.Close()
	for _, file := range archive.File {
		if file.Name != "word/document.xml" {
			continue
		}
		reader, err := file.Open()
		if err != nil {
			return err
		}
		paragraphs, parseErr := wordParagraphs(reader)
		reader.Close()
		if parseErr != nil {
			return parseErr
		}
		matches := 0
		appendix := false
		for _, paragraph := range paragraphs {
			if paragraph == "附录 C 对外头文件" {
				appendix = true
			}
			if paragraph == strings.TrimSuffix(header, "\n") {
				if !appendix {
					return errors.New("Word public header must appear in appendix C")
				}
				matches++
			}
		}
		if matches == 1 {
			return nil
		}
		return errors.New("Word header appendix is missing, duplicated or stale; regenerate Word from the synchronized Markdown")
	}
	return errors.New("Word document.xml is missing")
}

func run(root string, sync bool) error {
	header, err := readHeader(root)
	if err != nil {
		return err
	}
	path := filepath.Join(root, markdownPath)
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	markdown := normalize(data)
	if sync {
		updated, err := replaceReference(markdown, header)
		if err != nil {
			return err
		}
		if !bytes.Equal(data, []byte(updated)) {
			if err := os.WriteFile(path, []byte(updated), 0644); err != nil {
				return err
			}
		}
		fmt.Println("Markdown header synchronized; regenerate Word and run --check")
		return nil
	}
	if err := checkMarkdown(markdown, header); err != nil {
		return err
	}
	if err := checkWord(filepath.Join(root, wordPath), header); err != nil {
		return err
	}
	fmt.Println("Flight manual public header matches Markdown and Word exactly")
	return nil
}
