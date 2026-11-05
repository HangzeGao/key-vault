package main

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMarkdownReferenceStrictness(t *testing.T) {
	header := "#ifndef TC_SECURITY_H\n#define TC_SECURITY_H\n#endif\n"
	updated, err := replaceReference("# Manual\n", header)
	if err != nil || checkMarkdown(updated, header) != nil {
		t.Fatalf("initial sync: %v", err)
	}
	next, err := replaceReference(updated, header)
	if err != nil || next != updated {
		t.Fatal("sync is not idempotent")
	}
	if checkMarkdown(updated, header+"/* new contract */\n") == nil {
		t.Fatal("stale Markdown accepted")
	}
	for _, malformed := range []string{beginMarker, endMarker, endMarker + beginMarker, updated + beginMarker, "## 附录 C 对外头文件\n"} {
		if _, err := replaceReference(malformed, header); err == nil {
			t.Fatal("malformed markers accepted")
		}
	}
}

func writeWord(t *testing.T, xmlText string) string {
	t.Helper()
	var data bytes.Buffer
	archive := zip.NewWriter(&data)
	entry, err := archive.Create("word/document.xml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write([]byte(xmlText)); err != nil {
		t.Fatal(err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "manual.docx")
	if err := os.WriteFile(path, data.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestWordReferenceChecksTextAndWhitespace(t *testing.T) {
	header := "#ifndef TC_SECURITY_H\n    a < b;\n#endif\n"
	paragraph := `<w:p><w:r><w:t>#ifndef TC_SECURITY_H</w:t><w:br/><w:t xml:space="preserve">    a &lt; b;</w:t><w:br/><w:t>#endif</w:t></w:r></w:p>`
	wrap := func(body string) string {
		return `<w:document xmlns:w="urn:word"><w:body><w:p><w:r><w:t>附录 C 对外头文件</w:t></w:r></w:p>` + body + `</w:body></w:document>`
	}
	path := writeWord(t, wrap(paragraph))
	if err := checkWord(path, header); err != nil {
		t.Fatal(err)
	}
	if checkWord(path, strings.ReplaceAll(header, "    ", "  ")) == nil {
		t.Fatal("changed indentation accepted")
	}
	if checkWord(path, header+"/* new field */\n") == nil {
		t.Fatal("stale Word accepted")
	}
	if checkWord(writeWord(t, wrap(paragraph+paragraph)), header) == nil {
		t.Fatal("duplicate header accepted")
	}
	if checkWord(writeWord(t, `<broken`), header) == nil {
		t.Fatal("malformed XML accepted")
	}
}
