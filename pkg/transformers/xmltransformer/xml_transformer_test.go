package xmltransformer

import (
	"github.com/octarinesec/secret-detector/pkg/transformers/tests"
	"testing"
)

var testCases = []tests.TestCase{
	{"illegal xml - empty input", "", nil},
	{"illegal xml - simple string", "hello world", nil},
	{"illegal xml - double quoted string", `"hello world"`, nil},
	{"illegal xml - single quoted string", `'hello world'`, nil},
	{"illegal xml - missing open bracket", `<root`, nil},
	{"illegal xml - missing close bracket", `root/>`, nil},
	{"illegal xml - missing close tag", `<root>`, nil},
	{"illegal xml - missing tag name", `</>`, nil},
	{"illegal xml - tag mismatch", `<tag></t>`, nil},
	{"illegal xml - wrong brackets", `{tag /}`, nil},
	{"illegal xml - missing value quotes", `<tag attr=val/>`, nil},
	{"illegal xml - unescaped characters", `<tag attr="<"/>`, nil},
	{"illegal xml - attr in close tag", `<tag><tag a="v" />`, nil},

	{"empty element tag with no data", `<tag/>`, map[string]string{}},
	{"empty element tag with attributes", `<tag a1="v1"/>`, map[string]string{"tag[a1]": "v1"}},
	{"tag with no data", `<tag></tag>`, map[string]string{}},
	{"tag with attributes", `<tag a1="v1"></tag>`, map[string]string{"tag[a1]": "v1"}},
	{"tag with element", `<tag>e</tag>`, map[string]string{"tag": "e"}},
	{"tag with attributes and element",
		`<tag a1="v1">e</tag>`,
		map[string]string{"tag": "e", "tag[a1]": "v1"}},
	{"nested tags",
		`
<t1 a1="v1">
  e1
  <t2 a2="v2"/>
  <t3>
    <t4 a4_1="v4_1" a4_2="v4_2"/>
  </t3>
</t1>`,
		map[string]string{
			"t1":             "e1",
			"t1[a1]":         "v1",
			"t1.t2[a2]":      "v2",
			"t1.t3.t4[a4_1]": "v4_1",
			"t1.t3.t4[a4_2]": "v4_2",
		}},
	{"ignore comments, directives and instructions", `
<?xml version="1.0" encoding="UTF-8"?>
<t1>
  <!directice [ignore this tag] >
  <!-- ignore this comment -->
  <t2>e2</t2>
</t1>`, map[string]string{"t1.t2": "e2"}},
	{"ignore whitespace", "<t>\n\n\n\t\te\t\n\n\n</t>", map[string]string{"t": "e"}},
	{"handle CR/LF", "<t>\r\n\te\r\n</t>", map[string]string{"t": "e"}},
	{"escape characters",
		`<t a="&quot;v&quot;">&lt;&amp;&gt;</t>`,
		map[string]string{"t[a]": `"v"`, "t": "<&>"}},
	{"split element body",
		`<t1>hello<t2/>world</t1>`,
		map[string]string{"t1": "hello", "t1 (ln. 2)": "world"}},
	{"duplicate elements", `
<r>
  <t a="v0"/>
  <t a="v1"/>
  <t a="v2">e2</t>
</r>`,
		map[string]string{"r.t[a]": "v0", "r.t~1[a]": "v1", "r.t~2[a]": "v2", "r.t~2": "e2"}},
	{"duplicate attributes",
		`<t a="v0" a="v1"/>`,
		map[string]string{"t[a]": "v0", "t[a~1]": "v1"}},
}

var xmlTransformer = NewTransformer()

func TestTransform(t *testing.T) {
	tests.TestTransform(t, xmlTransformer, testCases)
}
