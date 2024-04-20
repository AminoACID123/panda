"""
Experimental script which detects rectangles and lines on a PDF page.

It may or may not work (correctly)!
We are only covering the most simple cases: A general drawback is, that we are
ignoring any geometry changes, which might be established by "cm" commands.
More simplifying assumption can be found at the functions below.
"""

#!/usr/bin/python3

import fitz
import numpy as np
import functools
import re
import pprint
import json
import argparse
import os

KEY_NAME = "name"
KEY_OPCODE = "opcode"
KEY_SIZE = "size"
KEY_COUNT = "count"
KEY_TYPE = "type"
KEY_DOMAIN = "domain"
KEY_PARAMETER = "parameters"
KEY_RETURN_PARAMETER = "return parameters"

TYPE_BYTES = "bytes"
TYPE_ENUM = "enum"

LE_META_OPCODE=0x3e

print(fitz.__doc__)
pp = pprint.PrettyPrinter(indent=4)

TEXT_TO_START = 5
RECT_TO_START = 8
RECT_SHRINK_WIDTH = 3
RECT_MIN_SIZE = 10
POINT_SIZE = 3

problem_set = {}

class Point(fitz.Point):
    def __init__(self, p) -> None:
        super().__init__(p)
    
    def __eq__(self, o: object) -> bool:
        if isinstance(o, Point):
            return self.xeq(o) and self.yeq(o)
        return False
    
    def xeq(self, o):
        return abs(self.x - o.x) < 1
    
    def yeq(self, o):
        return abs(self.y - o.y) < 1
    
    
def pcmp(p1 : Point, p2 : Point):
    if p1.yeq(p2):
        return p1.x - p2.x
    return p1.y - p2.y

class Form:
    def __init__(self, y0, y1) -> None:
        self.y0 = min(y0, y1)
        self.y1 = max(y0, y1)
        self.prev = 0
        self.X = []
        self.Y = []
        pass

    def __eq__(self, o: object) -> bool:
        if isinstance(o, Form):
            return abs(self.y0 - o.y0) < 1 and abs(self.y1 - o.y1) < 1
        return False
    
    def __getitem__(self, index):
        return self.cells[index]
    
    def __str__(self) -> str:
        text = ''
        for row in self.cells:
            for col in row:
                text = text + col + '\t'
            text += '\n'
        return text
    
    def add_vertex(self, v):
        if self.vertex_valid(v):
            self.X.append(v.x)
            self.Y.append(v.y)
    
    def get_vertices(self):
        return self.vertices

    def form(self, page):
        self.page = page
        i = 0
        self.X = sorted(self.X)
        while i < len(self.X) - 1:
            if abs(self.X[i] - self.X[i+1]) < 10:
                self.X.pop(i+1)
            else:
                i += 1

        i = 0
        self.Y = sorted(self.Y)
        while i < len(self.Y) - 1:
            if abs(self.Y[i] - self.Y[i+1]) < 10:
                self.Y.pop(i+1)
            else:
                i += 1
        self.vertices_to_cells()

    def vertices_to_cells(self):
        self.header = ''
        self.cells = []
        self.cols = len(self.X) - 1
        self.rows = len(self.Y) - 1
        if  self.rows < 1 or self.cols < 1:
            self.cells.append([''])
            return

        for i in range(self.rows):
            self.cells.append([])
            y0 = self.Y[i]
            y1 = self.Y[i+1]
            for j in range(self.cols):
                x0 = self.X[j]
                x1 = self.X[j+1]
                self.cells[-1].append(self.page.get_textbox(fitz.Rect(x0-5, y0-5, x1+5, y1+5)))
                if self.cells[-1][-1].strip() == 'none':
                    self.cells[-1][-1] = ''

        self.header = self.page.get_textbox(fitz.Rect(self.X[0]-10, self.Y[0]-60 , self.X[-1]+10, self.Y[0]))
        # print(self.header)
        # print('-------------------------')
        self.pname = None
        self.size = None
        self.alt_size = None
        self.count = None
        self.domain = []
        self.type = TYPE_BYTES

        values = ["", ""]

        pattern = r'Size: (.*?)octet'
        matches = re.findall(pattern, self.header)
        if len(matches) == 1:
            s = matches[0].strip().split()
            if len(s) == 1:
                self.size = s[0]
            elif len(s) == 3:
                self.size = s[-1]
                self.count = s[0]

        alt_pattern = r'([0-9])\s*octet'
        matches = re.findall(alt_pattern, self.header)
        if len(matches) == 1:
            self.alt_size = matches[0]

        t = 0
        values = ""
        if self.cells[0][0].strip() == 'Value':
            other_values, other_values_desc = self.cells[-1][0], self.cells[-1][1]
            if other_values.strip().lower() == 'all other values' and 'reserved for future use' in other_values_desc.strip().lower():
                t = 1

            for i in range(1, self.rows - t):
                value = self.cells[i][0].strip()
                values = values + value + ','
            for value in values.split(','):
                if value == "":
                    continue
                try:
                    self.domain.append(int(value, 0))
                except:
                    self.type = TYPE_BYTES
                    self.domain = []
                    return
                
            if len(self.domain) != 0:
                self.type = TYPE_ENUM

        # for i in range(len(self.header)-1):
        #     tok = self.header[i]
        #     next_tok = self.header[i+1]
        #     if next_tok == 'Size:':
        #         self.pname = tok[:-1]
        #         valid = False
        #         for j in range(i, len(self.header)):
        #             if self.header[j].startswith('octet'):
        #                 valid = True
        #                 try:
        #                     self.size = int(self.header[j-1])
        #                 except:
        #                     pass
        #                 # print(self.pname, self.size)
        #                 return
        #         valid = True

    def vertex_valid(self, p : Point):
        if abs(self.y0 - p.y) < 1 or abs(self.y1 - p.y) < 1:
            return True 
        return p.y > self.y0 and p.y < self.y1
    

def fcmp(f1, f2):
    return f1.y0 - f2.y0

class HCIAnalyzer:
    def __init__(self, path, start, end):
        doc = fitz.open(path)
        self.start = start
        self.end = end
        self.doc = fitz.open()
        self.doc.insert_pdf(doc, from_page=start-1,to_page=end)
        self.pageno = 0
        self.forms = []
        self.event_descs = []
        self.event_desc_on = False
    
    def __del__(self):
        self.doc.save("x.pdf")

    def find_lines(self, page, cont):
        ctm = page.transformation_matrix
        lines = []
        p1 = p2 = 0
        while p1 >= 0 and p1 < len(cont):
            try:
                p1 = cont.index("l", p2)
                p2 = p1 + 1
                y1 = float(cont[p1 - 1])
                x1 = float(cont[p1 - 2])
                if cont[p1 - 3] in ("m", "l"):
                    y0 = float(cont[p1 - 4])
                    x0 = float(cont[p1 - 5])
                else:
                    x0 = y0 = -1
                if x0 != -1:
                    point1 = fitz.Point(x0, y0) * ctm
                    point2 = fitz.Point(x1, y1) * ctm
                    lines.append((point1, point2))
                p1 = p2
            except:
                break

        return lines

    def rect_to_line(self, rect):
        delta_x = np.abs(rect.x0 - rect.x1)
        mean_x = np.mean([rect.x0 ,rect.x1])
        if delta_x < 10:
            p1 = fitz.Point(mean_x, rect.y0)
            p2 = fitz.Point(mean_x, rect.y1)
            return (p1, p2) if p1.y < p2.y else (p2, p1)
        delta_y = np.abs(rect.y0 - rect.y1)
        mean_y = np.mean([rect.y0, rect.y1])
        if delta_y < 10:
            p1 = fitz.Point(rect.x0, mean_y)
            p2 = fitz.Point(rect.x1, mean_y)
            return (p1, p2) if p1.x < p2.x else (p2, p1)
        return None

    def rect_to_keep(self, rect):
        return np.abs(rect.x0 -rect.x1) > RECT_MIN_SIZE and np.abs(rect.y0- rect.y1) > RECT_MIN_SIZE

    def transform_rect(self, x0, y0, x1, y1):
        ctm = self.page.transformation_matrix
        height = y1 - y0
        width = x1 - x0
        p = fitz.Point(x0, y0) * ctm + (0, -height)
        return fitz.Rect(p.x, p.y, p.x + width, p.y + height)

    def shrink_rect(self, rect):
        w = RECT_SHRINK_WIDTH
        return fitz.Rect(rect.x0 + w, rect.y0 + w, rect.x1 - w, rect.y1 - w)
    
    def vertex_valid(self, p):
        for r in self.form_areas:
            if r[1].yeq(p) or r[0].yeq(p):
                return True
            if p.p.y <= r[1].p.y and p.p.y >= r[0].p.y:
                return True
        return False

    def find_rects(self, page, cont):
        ctm = page.transformation_matrix
        rlist = []
        p1 = p2 = 0
        while p1 >= 0 and p1 < len(cont):
            try:
                p1 = cont.index("re", p2)
                p2 = p1 + 1
                height = float(cont[p1 - 1])
                width = float(cont[p1 - 2])
                y = float(cont[p1 - 3])
                x = float(cont[p1 - 4])
                p = fitz.Point(x, y) * ctm + (0, -height)
                rect = fitz.Rect(p.x, p.y, p.x + width, p.y + height)
                #rect = fitz.Rect(x, y, x + width, y + height)
                rlist.append(rect)
                p1 = p2
            except Exception as e:
                break
        return rlist
        
    def find_vertices(self, rects):
        vertices : list(Point) = []
        res : list(Point) = []
        for rect in rects:
            line = self.rect_to_line(rect)
            if line is not None:
                p1, p2 = Point(line[0]), Point(line[1])
                vertices += ([p1] + [p2])
                if p1.xeq(p2):
                    form = Form(p1.y, p2.y)
                    self.forms[-1].append(form) if form not in self.forms[-1] else None
            else:
                vertices += [Point(rect.tl)]
                vertices += [Point(rect.tr)]
                vertices += [Point(rect.bl)]
                vertices += [Point(rect.br)]
                form = Form(rect.y0, rect.y1)
                self.forms[-1].append(form) if form not in self.forms[-1] else None

        temp = sorted(self.forms[-1], key=functools.cmp_to_key(fcmp))
        self.forms[-1] = []
        for i in range(len(temp)-1):
            if i == 0:
                self.forms[-1].append(Form(temp[i].y0, temp[i].y1))
            if abs(temp[i].y1 - temp[i+1].y0) < 1 or temp[i].y1 > temp[i+1].y0:
                self.forms[-1][-1].y1 = max(temp[i].y1, temp[i+1].y1)
            else:
                self.forms[-1].append(temp[i+1])

        [res.append(v) for v in vertices if v not in res]
        for v in res:
            for form in self.forms[-1]:
                form.add_vertex(v)
        for form in self.forms[-1]:
            form.form(self.page)
        
    
    def draw_rects_2d(self, rects):
        for row in rects:
            for col in row:
                # col = self.transform_rect(col.x0, col.y0, col.x1, col.y1)
                self.shape.drawRect(col)
        self.shape.finish(color=(1, 0, 0), width=0.3)
        self.shape.commit()

    def draw_rects_1d(self, rects):
        for rect in rects:
            # rect = self.transform_rect(rect.x0, rect.y0, rect.x1, rect.y1)
            self.shape.drawRect(rect)
        self.shape.finish(color=(1, 0, 0), width=0.3)
        self.shape.commit()
    
    def draw_point(self, point):
        self.shape.drawLine(point + fitz.Point(0, POINT_SIZE), point + fitz.Point(0, -POINT_SIZE))
        self.shape.drawLine(point + fitz.Point(POINT_SIZE, 0), point + fitz.Point(-POINT_SIZE, 0))

    def draw_points(self, X, Y):
        for x in X:
            for y in Y:
                self.draw_point(fitz.Point(x, y))
        self.shape.finish(color=(0, 0, 1), width=2)

        self.shape.commit()
    
    def draw_lines(self, lines):
        for line in lines:
            self.shape.drawLine(line[0], line[1])
        self.shape.finish(color=(1, 0, 1), width=1.5)       
        self.shape.commit()         

    def analyze(self):
        for page in self.doc.pages():
            self.analyze_page_text(page)
            self.analyze_page_forms(page)
    
    def analyze_page_text(self, page):
        for i, block in enumerate(page.get_text('blocks', sort=True)):
            text =  block[4]
            if re.match("7.*command", text.strip()) is not None or \
                re.match("7.*event", text.strip()) is not None:
                self.event_desc_on = False
            elif "event(s) generated" in text.lower():
                self.event_desc_on = True
                self.event_descs.append('')
            elif self.event_desc_on:
                if text.strip() == "HCI commands and events" or \
                    "Revision Date" in text or \
                    "Bluetooth SIG Proprietary" in text or \
                    "BLUETOOTH CORE SPECIFICATION Version" in text or \
                    "Host Controller Interface Functional Specification" == text.strip() or \
                    re.match("page [0-9]*", text) is not None:
                    continue
                text = text.replace('-\n', '').replace('\n', ' ')
                self.event_descs[-1] += text

    def analyze_page_forms(self,  page):
        self.pageno += 1
        # print(self.pageno)
        # assert(page.get_contents) == 1
        self.page = page
        self.shape = page.new_shape()
        self.forms.append([])
        rects = []
        cont = []
        for xref in page.get_contents():
            try:
                cont += self.doc.xref_stream(xref).decode(errors='ignore').split()
            except:
                #print(self.doc.xref_stream(xref))
                continue

        rects = self.find_rects(page, cont)[RECT_TO_START:]
        # self.draw_rects_1d([rect for rect in rects])
        self.find_vertices(rects)
        #self.draw_points(self.forms[-1][0].X, self.forms[-1][0].Y)
        # for form in self.forms[-1]:
        #     print(form)
        
    def analyze_data(self):
        #cmd = {KEY_NAME: '', 'ogf': 0, 'ocf': 0, 'parameters': [], 'return_parameters:': []}
        ogf = 0
        self.commands = []
        self.events = []
        cur = ''
        p_cur = 0
        for forms in self.forms:
            for form in forms:
                ty = form[0][0].strip()
                if ty == '':
                    pass
                elif ty == "Command":
                    cur = "Command"
                    p_cur = 0
                    name = form[1][0].strip().replace('-', '').replace('\n','').replace(' ', '').split('[')[0].strip()
                    self.commands.append({KEY_NAME: name,KEY_TYPE: "command", KEY_OPCODE: {}, KEY_PARAMETER:[], KEY_RETURN_PARAMETER: []})

                    for i in range(1, form.rows):
                        ocf = eval(form[i][1].strip().replace('\n',''))
                        if "HCI_LE_" in name:
                            ogf = 8
                        elif ocf == 1:
                            ogf += 1

                        opcode = hex(((ocf) | ((ogf) << 10)))
                        self.commands[-1][KEY_OPCODE][opcode] = [0, 0]
            
                        for pname in form[i][2].replace('-', '').replace('\n','').replace(',[','[').split(','):
                            pname = pname.strip()
                            if pname != '' and i == 1:
                                self.commands[-1][KEY_PARAMETER].append(
                                    {KEY_NAME: pname, KEY_SIZE: 0, KEY_TYPE: "", KEY_DOMAIN: []}
                                )
                            if pname != '':
                                self.commands[-1][KEY_OPCODE][opcode][0] += 1

                        for pname in form[i][3].replace('-', '').replace('\n','').split(','):
                            pname = pname.strip()
                            if pname != '' and i == 1:
                                self.commands[-1][KEY_RETURN_PARAMETER].append(
                                    {KEY_NAME: pname, KEY_SIZE: 0, KEY_TYPE: '', KEY_DOMAIN: []}
                                )
                            if pname != '':
                                self.commands[-1][KEY_OPCODE][opcode][1] += 1


                elif ty == "Event":
                    cur = "Event"
                    p_cur = 0
                    name = form[1][0].strip().replace('-', '').replace('\n','').split('[')[0].strip()
                    self.events.append({KEY_NAME: name,KEY_TYPE:"event", KEY_OPCODE: {}, KEY_PARAMETER:[]})

                    for i in range(1, form.rows):
                        opcode = hex(eval(form[i][1].strip().replace('\n','')))
                        self.events[-1][KEY_OPCODE][opcode] = 0
                        for pname in form[i][2].replace('-\n', '').split():
                            pname = pname.strip().strip(',')
                            if pname != '' and i == 1:
                                self.events[-1][KEY_PARAMETER].append(
                                    {KEY_NAME: pname, KEY_SIZE: 0, KEY_TYPE: "", KEY_DOMAIN: []}
                                )
                            if pname != '':
                                self.events[-1][KEY_OPCODE][opcode] += 1
                    
                    if int(opcode, 0) == LE_META_OPCODE and form.rows > 2:
                        problem_set[name] = "Multi-version LE Meta Event"


                elif cur == "Event":
                    alt_size, size, domain, type, count =form.alt_size, form.size, form.domain, form.type, form.count

                    if size is not None:
                        # assert self.events[-1]['p'][p_cur][KEY_NAME] == pname
                        self.events[-1][KEY_PARAMETER][p_cur][KEY_SIZE] = size
                        self.events[-1][KEY_PARAMETER][p_cur][KEY_TYPE] = type
                        self.events[-1][KEY_PARAMETER][p_cur][KEY_DOMAIN] = domain
                        if count is not None:
                            self.events[-1][KEY_PARAMETER][p_cur][KEY_COUNT] = count
                        if size == -1:
                            problem_set['{}:{}'.format(self.events[-1][KEY_NAME], self.events[-1][KEY_PARAMETER][p_cur][KEY_NAME])] = 'Unresolved Parameter Size'
                        p_cur += 1
                    else:
                        problem_set[self.events[-1][KEY_NAME]] = 'Event: Possible Unhandled Parameter Form'

                elif cur == "Command":
                    alt_size, size, domain, type, count = form.alt_size, form.size, form.domain, form.type, form.count
                    p_len = len(self.commands[-1][KEY_PARAMETER])
                    rp_len = len(self.commands[-1][KEY_RETURN_PARAMETER])

                    if size is not None and p_cur < p_len + rp_len:
                        if p_cur < p_len:
                            # print(self.commands[-1]['p'][p_cur][KEY_NAME], pname)
                            # assert self.commands[-1]['p'][p_cur][KEY_NAME] == pname
                            self.commands[-1][KEY_PARAMETER][p_cur][KEY_SIZE] = size
                            self.commands[-1][KEY_PARAMETER][p_cur][KEY_TYPE] = type
                            self.commands[-1][KEY_PARAMETER][p_cur][KEY_DOMAIN] = domain
                            if count is not None:
                                self.commands[-1][KEY_PARAMETER][p_cur][KEY_COUNT] = count 
                            if size == -1:
                                problem_set['{}:{}'.format(self.commands[-1][KEY_NAME], self.commands[-1][KEY_PARAMETER][p_cur][KEY_NAME])] = 'Unresolved Parameter Size'

                        else:
                            # assert self.commands[-1]['rp'][p_cur - p_len][KEY_NAME] == pname
                            self.commands[-1][KEY_RETURN_PARAMETER][p_cur - p_len][KEY_SIZE] = size
                            self.commands[-1][KEY_RETURN_PARAMETER][p_cur - p_len][KEY_TYPE] = type
                            self.commands[-1][KEY_RETURN_PARAMETER][p_cur - p_len][KEY_DOMAIN] = domain
                            if count is not None:
                                self.commands[-1][KEY_RETURN_PARAMETER][p_cur - p_len][KEY_COUNT] = count
                            if size == -1:
                                problem_set['{}:{}'.format(self.commands[-1][KEY_NAME], self.commands[-1][KEY_RETURN_PARAMETER][p_cur - p_len][KEY_NAME])] = 'Unresolved Parameter Size'
                        p_cur += 1
                    elif size is None:
                        problem_set[self.commands[-1][KEY_NAME]] = 'Command: Possible Unhandled Parameter Form'
        
        for i in range(0, len(self.commands)):
            for j in range(0, len(self.commands[i][KEY_PARAMETER])):
                name = self.commands[i][KEY_PARAMETER][j][KEY_NAME]
                if name == 'Connection_Handle':
                    self.commands[i][KEY_PARAMETER][j][KEY_TYPE] = 'handle'
                elif name == 'BD_ADDR':
                    self.commands[i][KEY_PARAMETER][j][KEY_TYPE] = 'addr'
                elif name == 'Status':
                    self.commands[i][KEY_PARAMETER][j][KEY_TYPE] = 'status'
            for k in range(0, len(self.commands[i][KEY_RETURN_PARAMETER])):
                name = self.commands[i][KEY_RETURN_PARAMETER][k][KEY_NAME]
                if name == 'Connection_Handle':
                    self.commands[i][KEY_RETURN_PARAMETER][k][KEY_TYPE] = 'handle'
                elif name == 'BD_ADDR':
                    self.commands[i][KEY_RETURN_PARAMETER][k][KEY_TYPE] = 'addr'
                elif name == 'Status':
                    self.commands[i][KEY_RETURN_PARAMETER][k][KEY_TYPE] = 'status'
        
        for i in range(0, len(self.events)):
            for j in range(0, len(self.events[i][KEY_PARAMETER])):
                name = self.events[i][KEY_PARAMETER][j][KEY_NAME]
                if name == 'Connection_Handle':
                    self.events[i][KEY_PARAMETER][j][KEY_TYPE] = 'handle'
                elif name == 'BD_ADDR':
                    self.events[i][KEY_PARAMETER][j][KEY_TYPE] = 'addr'
                elif name == 'Status':
                    self.events[i][KEY_PARAMETER][j][KEY_TYPE] = 'status'



def gen_source_file(ha : HCIAnalyzer):
    cmds = []
    evts = []
    le_evts = []
    cmds_with_var_params = []
    cmds_with_mult_versions = []
    evts_with_var_params = []
    evts_with_mult_versions = []
    le_evts_with_var_params = []
    le_evts_with_mult_versions = []

    def is_int(x):
        if type(x) is int:
            return True
        try:
            if type(eval(x)) is int:
                return True
        except:
            return False
    
    with open('buzzer_fuzz_packets.h', 'w') as f:
        for cmd in ha.commands:
            skip = False
            if len(cmd['opcode']) > 1:
                cmds_with_mult_versions.append(list(cmd['opcode'])[0])
                continue
            for param in cmd['parameters']:
                if 'count' in param.keys() or not is_int(param['size']):
                    cmds_with_var_params.append(list(cmd['opcode'])[0])
                    skip = True
                    break
            for param in cmd['return parameters']:
                if 'count' in param.keys() or not is_int(param['size']):
                    cmds_with_var_params.append(list(cmd['opcode'])[0])
                    skip = True
                    break
            if not skip:
                cmds.append(cmd)
        
        for evt in ha.events:
            skip = False
            if len(evt['opcode']) > 1:
                evts_with_mult_versions.append(list(evt['opcode'])[0])
                continue
            for param in evt['parameters']:
                if 'count' in param.keys() or not is_int(param['size']):
                    if 'HCI_LE_' in evt['name']:
                        le_evts_with_var_params.append(list(evt['opcode'])[0])
                    else:
                        evts_with_var_params.append(list(evt['opcode'])[0])
                    skip = True
            if skip:
                continue
            if 'HCI_LE_' in evt['name']:
                le_evts.append(evt)
            else:
                evts.append(evt)
        

        for cmd in cmds:
            size = 0
            rsp_size = 0
            bd_addr_offset = -1
            handle_offset = -1
            rsp_bd_addr_offset = -1
            rsp_handle_offset = -1
            rsp_status_offset = -1
            opcode = list(cmd['opcode'])[0]
            for param in cmd['parameters']:
                if param['type'] == 'handle':
                    handle_offset = size
                if param['type'] == 'addr':
                    bd_addr_offset = size
                size = size + int(param['size'])
        
            for rparam in cmd['return parameters']:
                if rparam['type'] == 'status':
                    rsp_status_offset = rsp_size
                if rparam['type'] == 'handle':
                    rsp_handle_offset = rsp_size
                if rparam['type'] == 'addr':
                    rsp_bd_addr_offset = rsp_size
                rsp_size = rsp_size + int(rparam['size'])
            f.write("DEF_CMD({}, {}, {}, {}, {}, {}, {}, {});\n".format(
                    opcode, size, rsp_size, bd_addr_offset, handle_offset, rsp_status_offset, rsp_bd_addr_offset, rsp_handle_offset))

        for evt in evts:
            size = 0
            bd_addr_offset = -1
            handle_offset = -1
            status_offset = -1
            opcode = list(evt['opcode'])[0]
            for param in evt['parameters']:
                if param['type'] == 'status':
                    status_offset = size
                if param['type'] == 'handle':
                    handle_offset = size
                if param['type'] == 'addr':
                    bd_addr_offset = size
                size = size + int(param['size'])
            f.write("DEF_EVT({}, {}, {}, {}, {});\n".format(
                opcode, size, status_offset, bd_addr_offset, handle_offset))
            
        for evt in le_evts:
            size = 0
            bd_addr_offset = -1
            handle_offset = -1
            status_offset = -1
            opcode = evt['parameters'][0]['domain'][0]
            for param in evt['parameters']:
                if param['type'] == 'status':
                    status_offset = size
                if param['type'] == 'handle':
                    handle_offset = size
                if param['type'] == 'addr':
                    bd_addr_offset = size
                size = size + int(param['size'])
            f.write("DEF_LE_EVT({}, {}, {}, {}, {});\n".format(
                opcode, size, status_offset, bd_addr_offset, handle_offset))



def main():
    parser = argparse.ArgumentParser()

    parser.add_argument('--start', '-s',required=True, type=int, help="Start page")
    parser.add_argument('--end', '-e', required=True, type=int, help='End page')
    parser.add_argument('spec_file', type=str, help='Path to specification file')
    parser.add_argument('out_dir', type=str, help='Output directory to store parsed data models')

    args = parser.parse_args()

    ha = HCIAnalyzer(args.spec_file, args.start, args.end)
    ha.analyze()
    ha.analyze_data()
    # pp.pprint(ha.commands)
    # pp.pprint(ha.events)

    # json.dump(ha.commands, open(os.path.join(args.out_dir, 'hci_commands.json'), 'w'),indent=2)
    # json.dump(ha.events, open(os.path.join(args.out_dir, 'hci_events.json'), 'w'), indent=2)

    # for key in problem_set.keys():
    #     print(key)
    gen_source_file(ha)


if __name__ == "__main__":
    main()