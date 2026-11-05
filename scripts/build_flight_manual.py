#!/usr/bin/env python3
"""Build the flight manual from synchronized Markdown, using SimSun/Times fonts.

Run with the workspace's bundled Python (python-docx, Pillow, lxml):
  python scripts/build_flight_manual.py docs/FLIGHT_INTERFACE_MANUAL.md output.docx
"""
from pathlib import Path
import re
import sys

from docx import Document
from docx.enum.style import WD_STYLE_TYPE
from docx.enum.table import WD_CELL_VERTICAL_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.opc.constants import RELATIONSHIP_TYPE as RT
from docx.shared import Inches, Pt, RGBColor

source, output = map(Path, sys.argv[1:])
doc = Document()
section = doc.sections[0]
section.page_width = Inches(8.5)
section.page_height = Inches(11)
section.left_margin = section.right_margin = Inches(.86)
section.top_margin = Inches(.69)
section.bottom_margin = Inches(.69)
section.footer_distance = Inches(.32)
width = section.page_width - section.left_margin - section.right_margin

def xml(tag, **attrs):
    item = OxmlElement('w:' + tag)
    for name, value in attrs.items():
        item.set(qn('w:' + name), str(value))
    return item

def font(style, size, bold=False, name='Calibri'):
    style.font.name = name
    style.font.size = Pt(size)
    style.font.bold = bold
    style.font.color.rgb = RGBColor.from_string('000000')
    fonts = style.element.get_or_add_rPr().rFonts
    fonts.set(qn('w:eastAsia'), 'Microsoft YaHei')

for name in ('Normal', 'List Bullet', 'List Number'):
    st = doc.styles[name]
    font(st, 11)
    st.paragraph_format.line_spacing = 1.12
    st.paragraph_format.space_after = Pt(6)

for name, size, before, after in [('Title', 29, 0, 13), ('Heading 1', 16, 13, 7), ('Heading 2', 13, 9, 5), ('Heading 3', 11, 6, 4)]:
    st = doc.styles[name]
    font(st, size, True)
    st.paragraph_format.space_before = Pt(before)
    st.paragraph_format.space_after = Pt(after)
    st.paragraph_format.line_spacing = 1.12
    st.paragraph_format.keep_with_next = True
    border = st.element.find('.//' + qn('w:pBdr'))
    if border is not None:
        border.getparent().remove(border)

code = doc.styles.add_style('C Declaration', WD_STYLE_TYPE.PARAGRAPH)
font(code, 9.5, name='Consolas')
code.paragraph_format.left_indent = Inches(.12)
code.paragraph_format.space_before = Pt(3)
code.paragraph_format.space_after = Pt(9)
code.paragraph_format.line_spacing = 1.13
code.paragraph_format.keep_together = True

footer = section.footer.paragraphs[0]
footer.alignment = WD_ALIGN_PARAGRAPH.RIGHT
field = xml('fldSimple', instr='PAGE')
footer._p.append(field)
doc.core_properties.title = '星务端密码模块接口手册'
doc.core_properties.subject = '星载 C 密码模块接入与调用约定'
doc.core_properties.author = ''

token = re.compile(r'(\*\*.+?\*\*|`[^`]+`|\[[^\]]+\]\([^)]+\))')

def rich(p, value, bold=False, table=False):
    for part in token.split(value):
        if not part:
            continue
        if part.startswith('**') and part.endswith('**'):
            rich(p, part[2:-2], True, table)
        elif part.startswith('`') and part.endswith('`'):
            r = p.add_run(part[1:-1])
            r.font.name = 'Consolas'
            r.font.size = Pt(9.3 if table else 10.2)
            r.bold = bold
        elif (m := re.fullmatch(r'\[([^\]]+)\]\(([^)]+)\)', part)):
            link = xml('hyperlink')
            link.set(qn('r:id'), p.part.relate_to(m[2], RT.HYPERLINK, is_external=True))
            r = xml('r')
            props = xml('rPr')
            props.append(xml('color', val='244A67'))
            props.append(xml('u', val='single'))
            r.append(props)
            t = xml('t')
            t.text = m[1]
            r.append(t)
            link.append(r)
            p._p.append(link)
        else:
            r = p.add_run(part)
            r.bold = bold
            if table:
                r.font.size = Pt(10)

def table(data):
    rows = [[c.strip() for c in line.strip().strip('|').split('|')] for line in data]
    rows.pop(1)
    n = len(rows[0])
    if n == 3:
        if rows[0][0] == '功能':
            fractions = (.17, .395, .435)
        elif rows[0][0] == 'TC 错误码':
            fractions = (.40, .33, .27)
        elif rows[0][0] == '`commit->kind`':
            fractions = (.33, .33, .34)
        else:
            fractions = (.33, .37, .30)
    else:
        fractions = (.43, .57)
    t = doc.add_table(rows=0, cols=n)
    t.autofit = False
    for col, ratio in zip(t.columns, fractions):
        col.width = int(width * ratio)
    props = t._tbl.tblPr
    borders = xml('tblBorders')
    for edge in ('top', 'left', 'bottom', 'right', 'insideH', 'insideV'):
        borders.append(xml(edge, val='single', sz=4, color='CBD5DD'))
    props.append(borders)
    margins = xml('tblCellMar')
    for edge, size in [('top', 45), ('bottom', 45), ('left', 108), ('right', 108)]:
        margins.append(xml(edge, w=size, type='dxa'))
    props.append(margins)
    for idx, values in enumerate(rows):
        assert len(values) == n
        row = t.add_row()
        trpr = row._tr.get_or_add_trPr()
        trpr.append(xml('cantSplit'))
        if idx == 0:
            trpr.append(xml('tblHeader'))
        for j, (cell, value) in enumerate(zip(row.cells, values)):
            cell.width = int(width * fractions[j])
            cell.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER
            if idx == 0:
                cell._tc.get_or_add_tcPr().append(xml('shd', fill='DFEAF2'))
            elif idx % 2 == 0:
                cell._tc.get_or_add_tcPr().append(xml('shd', fill='F5F8FA'))
            p = cell.paragraphs[0]
            p.paragraph_format.space_after = Pt(0)
            p.paragraph_format.line_spacing = 1.05
            p.paragraph_format.keep_with_next = idx == 0
            rich(p, value, idx == 0, True)
    spacer = doc.add_paragraph()
    spacer.paragraph_format.space_after = Pt(0)
    spacer.paragraph_format.line_spacing = Pt(5)


from PIL import Image, ImageDraw, ImageFont
from pathlib import Path

work = Path(__file__).resolve().parents[1] / ".cache" / "flight-manual-assets"
work.mkdir(parents=True, exist_ok=True)
font_dir = Path("C:/Windows/Fonts")

def sequence_image(lines, number):
    body = [line.strip() for line in lines]
    assert body.pop(0) == "sequenceDiagram"
    people = []
    while body[0].startswith("participant "):
        people.append(re.fullmatch(r"participant (\w+) as (.+)", body.pop(0)).groups())
    width, pitch, first_y = 1400, 51, 108
    positions = dict(zip((key for key, name in people),
                         (183, 700, 1217) if len(people) == 3 else (200, 900)))
    height = first_y + pitch * len(body) + 4
    image = Image.new("RGB", (width, height), "white")
    draw = ImageDraw.Draw(image)

    def label(value, x, y, maximum=660, bold=False, background=None):
        chunks = re.findall(r"[\x00-\x7f]+|[^\x00-\x7f]+", value)
        for size in range(33, 22, -1):
            fonts = [ImageFont.truetype(str(font_dir / (("timesbd.ttf" if bold else "times.ttf")
                     if part.isascii() else "simsun.ttc")), size) for part in chunks]
            lengths = [draw.textlength(part, font=font) for part, font in zip(chunks, fonts)]
            if sum(lengths) <= maximum:
                break
        assert sum(lengths) <= maximum, value
        left = x - sum(lengths) / 2
        if background:
            draw.rectangle((left-6, y-30, left+sum(lengths)+6, y+6), fill=background)
        for part, font, length in zip(chunks, fonts, lengths):
            draw.text((left, y), part, font=font, fill="black", anchor="ls")
            left += length

    def dashed(a, b, y, vertical=False):
        for start in range(min(a,b), max(a,b), 14):
            end = min(start+8, max(a,b))
            points = (y,start,y,end) if vertical else (start,y,end,y)
            draw.line(points, fill="#767676" if vertical else "black", width=3)

    for key, name in people:
        x = positions[key]
        dashed(70, height-7, x, vertical=True)
        draw.rectangle((x-155, 7, x+155, 70), outline="black", width=3, fill="white")
        label(name, x, 50, maximum=287, bold=True)

    for i, line in enumerate(body):
        y = first_y + i*pitch
        if line.startswith("Note over "):
            draw.rectangle((12,y-30,width-12,y+11), fill="#eeeeee", outline="black", width=2)
            label(line.split(": ",1)[1], width//2, y+1, maximum=1300)
        elif line.startswith(("opt ", "alt ", "else ")):
            mode, message = line.split(" ",1)
            if mode != "else":
                end = body.index("end", i+1)
                draw.rectangle((12,y-30,width-12,first_y+end*pitch-26), outline="black", width=2)
            else:
                dashed(12,width-12,y-30)
            draw.rectangle((12,y-30,530,y+11), fill="#eeeeee", outline="black", width=2)
            tag = {"opt":"条件", "alt":"分支", "else":"分支"}[mode]
            label(tag + "  " + message, 271, y, maximum=480)
        elif line != "end":
            origin, arrow, dest, value = re.fullmatch(r"(\w+)(-->>|->>)(\w+): (.+)", line).groups()
            x1, x2 = positions[origin], positions[dest]
            if x1 == x2:
                draw.line((x1,y-14,x1+73,y-14,x1+73,y+10,x1,y+10), fill="black", width=3)
                direction = -1
                label(value, x1+300 if x1 == min(positions.values()) else x1-252,
                      y, maximum=430, background="white")
            else:
                if arrow == "-->>":
                    dashed(x1,x2,y+10)
                else:
                    draw.line((x1,y+10,x2,y+10), fill="black", width=3)
                direction = 1 if x2>x1 else -1
                label(value, (x1+x2)//2, y, maximum=abs(x2-x1)-22, background="white")
            draw.polygon([(x2,y+10),(x2-direction*17,y+3),(x2-direction*17,y+17)], fill="black")
    file = work / f"flight-designer-sequence-{number}.png"
    image.save(file)
    return file

lines = source.read_text(encoding="utf-8-sig").splitlines()
i, count, appendix_b, appendix_c = 0, 0, False, False
while i < len(lines):
    line = lines[i]
    if line.startswith(chr(96)*3):
        kind = line[3:]
        i += 1
        block = []
        while not lines[i].startswith(chr(96)*3):
            block.append(lines[i])
            i += 1
        if kind == "mermaid":
            count += 1
            diagram = sequence_image(block, count)
            paragraph = doc.add_paragraph()
            paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
            paragraph.paragraph_format.space_after = Pt(4)
            shape = paragraph.add_run().add_picture(str(diagram), width=Inches(6.6))
            shape._inline.docPr.set("descr", "；".join(event.strip() for event in block[1:]))
        else:
            paragraph = doc.add_paragraph("\n".join(block), style="C Declaration")
            if appendix_b:
                paragraph.paragraph_format.line_spacing = 1.0
            if "#ifndef TC_SECURITY_H" in "\n".join(block):
                paragraph.paragraph_format.keep_together = False
    elif line.startswith("<!--"):
        pass
    elif line.startswith("|"):
        block = [line]
        while i+1 < len(lines) and lines[i+1].startswith("|"):
            i += 1
            block.append(lines[i])
        table(block)
    elif line.startswith("# "):
        doc.add_paragraph(line[2:], style="Title")
    elif line.startswith("## "):
        appendix_b = line.startswith("## 附录 B")
        appendix_c = line.startswith("## 附录 A")
        heading = doc.add_paragraph(re.sub(r"^(\d+)\. ", r"\1  ", line[3:]), style="Heading 1")
        heading.paragraph_format.page_break_before = line.startswith(
            ("## 模块职责", "## 2.", "## 3.", "## 4.", "## 附录"))
    elif line.startswith(("### ", "#### ")):
        level, value = line.split(" ",1)
        heading = doc.add_paragraph(style="Heading 2" if level == "###" else "Heading 3")
        rich(heading, value, bold=True)
        heading.paragraph_format.page_break_before = value.startswith(("1.1 ", "1.2 ", "1.3 ", "1.4 ", "1.5 ", "2.1 ", "2.2 ", "6.1 ", "6.2 ", "6.3 ", "A.3 ", "3.2 ", "3.3 ", "3.4 ", "6.4 ", "6.5 ", "6.6 ", "B.3 ", "B.5 ", "B.7 ", "B.8 ", "上下文与公开数据对象", "配置快照对象", "恢复通道对象", "换根准备对象", "提交返回值", "星地派生输入"))
    elif line.startswith("- "):
        rich(doc.add_paragraph(style="List Bullet"), line[2:])
    elif (match := re.match(r"^\d+\. (.+)$",line)):
        if appendix_c:
            paragraph = doc.add_paragraph()
            paragraph.paragraph_format.left_indent = Inches(.19)
            paragraph.paragraph_format.first_line_indent = Inches(-.19)
            rich(paragraph, line)
        else:
            rich(doc.add_paragraph(style="List Number"), match[1])
    elif line.strip():
        paragraph = doc.add_paragraph()
        rich(paragraph,line)
        if i+2 < len(lines) and not lines[i+1] and lines[i+2].startswith(chr(96)*3):
            paragraph.paragraph_format.keep_with_next = True
    i += 1
assert count == 11
assert len(doc.tables) == len(re.findall(r"(?m)^\| ---","\n".join(lines)))
doc.save(output)






from zipfile import ZipFile
from lxml import etree
import io

def normalize_docx(path):
    ns = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}
    w = "{" + ns["w"] + "}"
    parts = {"word/document.xml", "word/styles.xml", "word/stylesWithEffects.xml",
             "word/numbering.xml"}

    with ZipFile(io.BytesIO(path.read_bytes())) as original, ZipFile(path, "w") as result:
        for entry in original.infolist():
            data = original.read(entry)
            name = entry.filename
            if name in parts or name.startswith(("word/header", "word/footer")) and name.endswith(".xml"):
                root = etree.fromstring(data)
                before = root.xpath("//w:t/text()", namespaces=ns)
                for rp in root.xpath("//w:rPr", namespaces=ns):
                    fonts = rp.find(w + "rFonts")
                    if fonts is None:
                        fonts = etree.Element(w + "rFonts")
                        rp.insert(1 if rp.find(w + "rStyle") is not None else 0, fonts)
                    fonts.attrib.clear()
                    for role in ("ascii", "hAnsi", "cs"):
                        fonts.set(w + role, "Times New Roman")
                    fonts.set(w + "eastAsia", "SimSun")
                for element in root.xpath("//w:color | //w:u | //w:shd | //w:highlight | //w:tblBorders/* | //w:tcBorders/* | //w:pBdr/*", namespaces=ns):
                    local = etree.QName(element).localname
                    for attr in list(element.attrib):
                        if "theme" in etree.QName(attr).localname.lower():
                            del element.attrib[attr]
                    if local == "color":
                        element.set(w + "val", "000000")
                    elif local == "shd":
                        element.set(w + "val", "clear")
                        element.set(w + "fill", "FFFFFF")
                        element.set(w + "color", "000000")
                    elif local == "highlight":
                        element.set(w + "val", "none")
                    elif local != "u" or w + "color" in element.attrib:
                        element.set(w + "color", "000000")
                for level in root.xpath("//w:lvl[w:numFmt/@w:val='bullet']/w:lvlText", namespaces=ns):
                    value = level.get(w + "val", "")
                    if any(0xE000 <= ord(c) <= 0xF8FF for c in value):
                        level.set(w + "val", "•")
                if name == "word/document.xml":
                    for table in root.xpath("//w:tbl", namespaces=ns):
                        label = "".join(table.xpath("./w:tr[1]/w:tc[1]//w:t/text()", namespaces=ns))
                        ratios = {"接收结果": (.36, .34, .30), "commit->kind": (.37, .26, .37)}.get(label)
                        if ratios:
                            grid = table.xpath("./w:tblGrid/w:gridCol", namespaces=ns)
                            total = sum(int(col.get(w + "w")) for col in grid)
                            widths = [round(total * x) for x in ratios]
                            for col, size in zip(grid, widths):
                                col.set(w + "w", str(size))
                            for row in table.findall(w + "tr"):
                                for cell, size in zip(row.findall(w + "tc"), widths):
                                    cell.find(f"{w}tcPr/{w}tcW").set(w + "w", str(size))
                    for shade in root.xpath("//w:tcPr/w:shd", namespaces=ns):
                        shade.getparent().remove(shade)
                    for edge in root.xpath("//w:tblBorders/*", namespaces=ns):
                        edge.set(w + "sz", "6")
                    steps = root.xpath("//w:p[w:pPr/w:pStyle/@w:val='ListNumber']", namespaces=ns)
                    for p in steps[:-1]:
                        props = p.find(w + "pPr")
                        if props.find(w + "keepNext") is None:
                            props.append(etree.Element(w + "keepNext"))
                assert before == root.xpath("//w:t/text()", namespaces=ns), name
                data = etree.tostring(root, encoding="UTF-8", xml_declaration=True, standalone=True)
            result.writestr(entry, data)

normalize_docx(output)
