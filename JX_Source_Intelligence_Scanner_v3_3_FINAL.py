import os, re, json, hashlib, shutil, threading, queue, time, struct, csv, tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
from datetime import datetime
from collections import defaultdict, Counter

APP_TITLE = 'JX Source Intelligence Scanner'
VERSION = '3.3'

TEXT_EXTENSIONS = {'.c','.cc','.cpp','.cxx','.h','.hh','.hpp','.hxx','.rc','.rc2','.def','.idl','.inc','.ini','.cfg','.conf','.txt','.xml','.json','.lua','.sql','.sln','.dsw','.dsp','.vcproj','.vcxproj','.filters','.props','.targets','.cmake','.mak','.mk','.bat','.cmd','.sh'}
CPP_EXTENSIONS = {'.c','.cc','.cpp','.cxx','.h','.hh','.hpp','.hxx','.inc'}
HEADER_EXTENSIONS = {'.h','.hh','.hpp','.hxx','.inc'}
SOURCE_EXTENSIONS = {'.c','.cc','.cpp','.cxx'}
PROJECT_EXTENSIONS = {'.sln','.dsw','.dsp','.vcproj','.vcxproj','.filters','.props','.targets','.cmake','.mak','.mk'}
BUILD_DIR_NAMES = {'.git','.svn','.hg','.vs','.idea','.vscode','debug','release','clientdebug','serverdebug','clientrelease','serverrelease','x64','x86','win32','bin','obj','build','out','dist','__pycache__'}
DEPENDENCY_KEYWORDS = {'directx','dxsdk','dependencies','dependency','thirdparty','third_party','3rdparty','external','externals','vendor','vendors','sdk','sdks','boost','openssl','zlib','freetype','libpng','jpeg','curl'}
BINARY_EXTENSIONS = {'.exe','.dll','.lib','.obj','.pdb','.ilk','.exp','.ncb','.opt','.plg','.pch','.sbr','.idb','.png','.jpg','.jpeg','.gif','.bmp','.tga','.dds','.ico','.wav','.mp3','.ogg','.flac','.avi','.mp4','.zip','.7z','.rar','.tar','.gz','.db','.mdb','.accdb','.myd','.myi','.xls','.xlsx'}
ENCODINGS = ['utf-8-sig','utf-8','gbk','big5','cp1252','latin-1']

GENERATED_DIRS = {'MODULES','AI_PACKS','INVESTIGATIONS','CHATGPT_UPLOADED'}
GENERATED_FILES = {
    '00_SOURCE_TREE.txt','01_FILE_MANIFEST.tsv','02_SYMBOL_INDEX.tsv','03_INCLUDE_GRAPH.tsv',
    '04_SCRIPT_BINDING_CANDIDATES.tsv','05_WIN_LINUX_COUNTERPARTS.tsv','06_PROJECT_MAP.json',
    '06_PROJECT_MAP.md','07_MODULE_PACKAGE_INDEX.tsv','08_STATS.json','09_SOURCE_DIFF.tsv',
    '09_SOURCE_DIFF.md','10_SYMBOL_REFERENCES.tsv','11_CALL_GRAPH.tsv','12_SOURCE_PAIRS.tsv',
    '13_INCLUDE_RESOLVED.tsv','14_MODULE_DEPENDENCIES.tsv','15_BUILD_CONFIGS.tsv',
    '16_SUBSYSTEM_MAP.tsv','17_SCRIPT_API_MAP.tsv','18_FEATURE_ENTRY_POINTS.tsv',
    '19_AI_PACK_INDEX.tsv','20_AI_SOURCE_GUIDE.md','98_SCAN_WARNINGS.tsv','99_IGNORED_FILES.txt',
    'AI_BOOTSTRAP.md','AI_READ_ORDER.md','.jxsi_cache.json'
}

SUBSYSTEM_RULES = [
    ('NPC', ('npc','missle','missile','partner','pet','ai')),
    ('PLAYER', ('player','role','character','avatar')),
    ('SKILL', ('skill','magic','spell')),
    ('ITEM', ('item','inventory','equip','goods','buysell','sellitem','viewitem')),
    ('SCRIPT', ('lua','script','funs','functable')),
    ('NETWORK', ('network','socket','protocol','packet','relay','gateway','server','client')),
    ('RENDERER', ('represent','render','d3d','direct3d','texture','sprite','spr','camera','light','shader','vertex')),
    ('UI', ('ui','window','dialog','menu','button','interface','wnd')),
    ('WORLD', ('world','subworld','region','scene','map','weather','terrain')),
    ('RESOURCE', ('resource','res','image','sound','music','file','pak','package')),
    ('DATABASE', ('database','db','sql','odbc')),
    ('CORE', ('core','engine','kernel')),
]

STOP_CALLS = set('if for while switch catch sizeof return new delete assert min max abs printf sprintf strlen memcpy memset strcpy strcmp'.split())


def safe_read_text(path):
    last = None
    for enc in ENCODINGS:
        try:
            return path.read_text(encoding=enc), enc, None
        except Exception as e:
            last = repr(e)
    return None, None, last


def sha1_file(path):
    h = hashlib.sha1()
    try:
        with path.open('rb') as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b''):
                h.update(chunk)
        return h.hexdigest(), None
    except Exception as e:
        return '', repr(e)


def clean_name(s):
    return re.sub(r'[<>:"/\\|?*]+', '_', s)


def norm_rel(s):
    return s.replace('\\','/').replace('//','/').lower()


def is_dep(rel):
    return any(any(k in p.lower() for k in DEPENDENCY_KEYWORDS) for p in rel.parts[:-1])


def classify_module(rel):
    p = rel.parts
    if not p:
        return '_ROOT'
    first = p[0]
    if first.lower() in {'multiserver','network','represent','library'} and len(p) >= 2:
        return '%s/%s' % (first, p[1])
    if first.lower() == 'linux' and len(p) >= 2:
        return 'LINUX/%s' % p[1]
    if first.lower() == 'kernel' and len(p) >= 2 and p[1].lower() in {'core','engine','lua'}:
        return 'Kernel/%s' % p[1]
    return first


def classify_subsystem(rel_s, symbols=None):
    hay = rel_s.lower().replace('\\','/')
    if symbols:
        hay += ' ' + ' '.join(x.lower() for x in symbols)
    scores = []
    for name, kws in SUBSYSTEM_RULES:
        score = sum(hay.count(k) for k in kws)
        if score:
            scores.append((score, name))
    if not scores:
        return 'OTHER'
    scores.sort(key=lambda x: (-x[0], x[1]))
    return scores[0][1]


def lineno(text, pos):
    return text.count('\n', 0, pos) + 1


def extract_symbols(text):
    out = []
    for kind, rx in [
        ('class', re.compile(r'^\s*class\s+(?:\w+\s+)*([A-Za-z_]\w*)', re.M)),
        ('struct', re.compile(r'^\s*struct\s+([A-Za-z_]\w*)', re.M)),
        ('enum', re.compile(r'^\s*enum(?:\s+class)?\s+([A-Za-z_]\w*)', re.M))]:
        for m in rx.finditer(text):
            out.append((kind, m.group(1), lineno(text, m.start())))
    frx = re.compile(r'^[ \t]*(?!if\b|for\b|while\b|switch\b|catch\b)(?:static\s+|inline\s+|virtual\s+|extern\s+|__inline\s+|__declspec\([^)]+\)\s+)*[\w:\<\>\~\*&\s,]+\s+((?:[A-Za-z_]\w*::)*~?[A-Za-z_]\w*)\s*\([^;{}]*\)\s*(?:const\s*)?\{', re.M)
    for m in frx.finditer(text):
        out.append(('function', m.group(1), lineno(text, m.start())))
    return out


def extract_function_ranges(text):
    # Heuristic brace-matching around function definitions; robust enough for legacy C/C++ indexing.
    frx = re.compile(r'^[ \t]*(?!if\b|for\b|while\b|switch\b|catch\b)(?:static\s+|inline\s+|virtual\s+|extern\s+|__inline\s+|__declspec\([^)]+\)\s+)*[\w:\<\>\~\*&\s,]+\s+((?:[A-Za-z_]\w*::)*~?[A-Za-z_]\w*)\s*\([^;{}]*\)\s*(?:const\s*)?\{', re.M)
    out = []
    for m in frx.finditer(text):
        start_brace = text.find('{', m.start(), m.end()+1)
        if start_brace < 0:
            continue
        depth = 0; i = start_brace; state = 'code'; quote = ''
        while i < len(text):
            c = text[i]; n = text[i+1] if i+1 < len(text) else ''
            if state == 'code':
                if c == '/' and n == '/': state = 'line'; i += 2; continue
                if c == '/' and n == '*': state = 'block'; i += 2; continue
                if c in ('"', "'"): state = 'str'; quote = c; i += 1; continue
                if c == '{': depth += 1
                elif c == '}':
                    depth -= 1
                    if depth == 0:
                        out.append((m.group(1), m.start(), i+1, lineno(text,m.start()), lineno(text,i)))
                        break
            elif state == 'line':
                if c == '\n': state = 'code'
            elif state == 'block':
                if c == '*' and n == '/': state = 'code'; i += 2; continue
            elif state == 'str':
                if c == '\\': i += 2; continue
                if c == quote: state = 'code'
            i += 1
    return out


def extract_includes(text):
    rx = re.compile(r'^\s*#\s*include\s*([<"])([^>"]+)[>"]', re.M)
    return [(m.group(2).strip(), lineno(text,m.start()), 'angle' if m.group(1)=='<' else 'quote') for m in rx.finditer(text)]


def extract_script_bindings(text):
    out = []; seen = set()
    patterns = [
      ('lua_register', re.compile(r'\blua_register\s*\(\s*[^,]+,\s*"([^"]+)"\s*,\s*([A-Za-z_]\w*(?:::\w+)*)\s*\)', re.I)),
      ('name_function_pair', re.compile(r'\{\s*"([^"]+)"\s*,\s*([A-Za-z_]\w*(?:::\w+)*)\s*\}')),
      ('register_call', re.compile(r'\b(?:RegisterFunction|RegisterFunc|AddFunction|AddFunc|RegisterGlobal|SetGlobalFunction|RegisterScriptFunction|AddScriptFunction)\s*\(\s*"([^"]+)"\s*,\s*(?:&\s*)?([A-Za-z_]\w*(?:::\w+)*)', re.I))]
    for kind, rx in patterns:
        for m in rx.finditer(text):
            row = (kind, m.group(1), m.group(2), lineno(text,m.start()))
            if row not in seen:
                seen.add(row); out.append(row)
    return out


def extract_build_configs(text):
    configs = []
    names = re.findall(r'^#\s*Name\s+"([^"]+)"', text, re.M)
    if not names:
        names = re.findall(r'^!IF\s+"\$\(CFG\)"\s*==\s*"([^"]+)"|^!ELSEIF\s+"\$\(CFG\)"\s*==\s*"([^"]+)"', text, re.M)
        names = [a or b for a,b in names]
    for name in sorted(set(names)):
        # Pull branch text where practical. For DSP this is heuristic but very useful.
        pat = re.compile(r'(?:!IF|!ELSEIF)\s+"\$\(CFG\)"\s*==\s*"%s"(?P<body>.*?)(?=\n!ELSEIF|\n!ENDIF)' % re.escape(name), re.S)
        m = pat.search(text); body = m.group('body') if m else text
        defines = sorted(set(re.findall(r'/D\s+"?([A-Za-z_]\w*)', body)))
        incs = re.findall(r'/I\s+"([^"]+)"|/I\s+([^\s]+)', body)
        include_paths = sorted(set((a or b).strip('"') for a,b in incs if a or b))
        libs = sorted(set(re.findall(r'(?<![\w.])([A-Za-z0-9_./\\-]+\.lib)\b', body, re.I)))
        libpaths = sorted(set(re.findall(r'/libpath:"?([^"\s]+)', body, re.I)))
        outputs = sorted(set(re.findall(r'/out:"?([^"\s\r\n]+)', body, re.I)))
        configs.append({'configuration':name,'defines':defines,'include_paths':include_paths,'libraries':libs,'lib_paths':libpaths,'outputs':outputs})
    return configs


def project_info(text):
    d = {'projects':[],'dependencies':[],'sources':[],'outputs':[],'libraries':[],'build_configs':[]}
    for m in re.finditer(r'Project:\s*"([^"]+)"=([^\r\n]+)', text):
        d['projects'].append({'name':m.group(1),'definition':m.group(2).strip()})
    d['dependencies'] = [m.group(1).strip() for m in re.finditer(r'Project_Dep_Name\s+([^\r\n]+)', text)]
    d['sources'] = [m.group(1).strip() for m in re.finditer(r'^\s*SOURCE\s*=\s*(.+)$', text, re.M)]
    d['outputs'] = [m.group(1).strip() for m in re.finditer(r'(?:/out:|OutputFile=)"?([^"\s\r\n]+)', text, re.I)]
    d['libraries'] = [m.group(1) for m in re.finditer(r'(?<![\w.])([A-Za-z0-9_./\\-]+\.lib)\b', text, re.I)]
    d['build_configs'] = extract_build_configs(text)
    return d


def write_tsv(path, header, rows):
    with path.open('w', encoding='utf-8', newline='') as f:
        f.write('\t'.join(header)+'\n')
        for row in rows:
            f.write('\t'.join(str(x).replace('\t',' ').replace('\r',' ').replace('\n',' ') for x in row)+'\n')


def is_subpath(child, parent):
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except Exception:
        return False


def build_chatgpt_uploaded(output, files, title, note_lines=None):
    """Create a compact first-upload bundle while keeping the full output tree intact."""
    dest = output/'CHATGPT_UPLOADED'
    if dest.exists():
        shutil.rmtree(str(dest))
    dest.mkdir(parents=True, exist_ok=True)
    copied=[]
    for name in files:
        src=output/name
        if src.is_file():
            shutil.copy2(str(src), str(dest/name))
            copied.append(name)
    readme=['# %s\n\n' % title,
            'Upload the files in this folder to ChatGPT first. The parent output folder still contains the complete scanner results and source packages.\n\n',
            '## Recommended upload order\n\n']
    for i,name in enumerate(copied,1): readme.append('%d. `%s`\n' % (i,name))
    if note_lines:
        readme.append('\n## Notes\n\n')
        for x in note_lines: readme.append('- %s\n' % x)
    (dest/'00_UPLOAD_FIRST.md').write_text(''.join(readme),encoding='utf-8')
    return copied


def lua_lineno(text,pos):
    return text.count('\n',0,pos)+1

def strip_lua_comments(text):
    # Preserve line count while removing comments enough for heuristic parsing.
    text=re.sub(r'--\[\[.*?\]\]',lambda m:'\n'*m.group(0).count('\n'),text,flags=re.S)
    return re.sub(r'--[^\n]*','',text)

def extract_lua_functions(text):
    clean=strip_lua_comments(text); out=[]
    rx=re.compile(r'(?m)^\s*(?:local\s+)?function\s+([A-Za-z_]\w*(?:[.:][A-Za-z_]\w*)*)\s*\(')
    for m in rx.finditer(clean): out.append(('function',m.group(1),lua_lineno(clean,m.start())))
    rx2=re.compile(r'(?m)^\s*(?:local\s+)?([A-Za-z_]\w*(?:[.:][A-Za-z_]\w*)*)\s*=\s*function\s*\(')
    for m in rx2.finditer(clean): out.append(('function_assignment',m.group(1),lua_lineno(clean,m.start())))
    return out

def extract_lua_requires(text):
    clean=strip_lua_comments(text); out=[]
    patterns=[('require',re.compile(r'\brequire\s*\(?\s*[\"\']([^\"\']+)[\"\']\s*\)?')),
              ('dofile',re.compile(r'\bdofile\s*\(\s*[\"\']([^\"\']+)[\"\']\s*\)')),
              ('loadfile',re.compile(r'\bloadfile\s*\(\s*[\"\']([^\"\']+)[\"\']\s*\)'))]
    for kind,rx in patterns:
        for m in rx.finditer(clean): out.append((kind,m.group(1),lua_lineno(clean,m.start())))
    return out

def extract_lua_calls(text):
    clean=strip_lua_comments(text); out=[]; stop={'if','for','while','function','return','elseif','print','pairs','ipairs','type','tonumber','tostring','assert','error','pcall','xpcall','select','unpack','next'}
    rx=re.compile(r'\b([A-Za-z_]\w*(?:[.:][A-Za-z_]\w*)*)\s*\(')
    for m in rx.finditer(clean):
        n=m.group(1)
        if n.split('.')[-1].split(':')[-1].lower() in stop: continue
        # Skip function declaration token.
        prefix=clean[max(0,m.start()-12):m.start()]
        if re.search(r'function\s*$',prefix): continue
        out.append((n,lua_lineno(clean,m.start())))
    return out

def extract_lua_globals(text):
    clean=strip_lua_comments(text); out=[]
    rx=re.compile(r'(?m)^\s*(?!local\b)([A-Za-z_]\w*)\s*=')
    for m in rx.finditer(clean): out.append((m.group(1),lua_lineno(clean,m.start())))
    return out

def classify_lua_module(rel):
    p=rel.parts
    if not p:return '_ROOT'
    return p[0] if len(p)==1 else '%s/%s' % (p[0],p[1])


class Scanner:
    def __init__(self, source, output, max_bytes, include_dep, unknown_text, ai_packs, incremental, clean_generated, cancel_event, emit):
        self.source = source; self.output = output; self.max_bytes = max_bytes
        self.include_dep = include_dep; self.unknown_text = unknown_text; self.ai_packs = ai_packs
        self.incremental = incremental; self.clean_generated = clean_generated
        self.cancel_event = cancel_event; self.emit = emit; self.warnings = []
        self.cache_path = output/'.jxsi_cache.json'; self.old_cache = {}; self.new_cache = {}

    def cancelled(self):
        if self.cancel_event.is_set():
            raise RuntimeError('__CANCELLED__')

    def log(self, msg, progress=None):
        self.emit(('log', msg, progress))

    def warn(self, rel, stage, err, action='continued'):
        self.warnings.append((rel, stage, err, action))

    def load_cache(self):
        if self.incremental and self.cache_path.exists():
            try:
                self.old_cache = json.loads(self.cache_path.read_text(encoding='utf-8'))
            except Exception as e:
                self.warn('.jxsi_cache.json','load_cache',repr(e),'ignored cache')
                self.old_cache = {}

    def clean_output(self):
        if not self.clean_generated:
            return
        for name in GENERATED_DIRS:
            p = self.output/name
            if p.exists():
                try: shutil.rmtree(str(p))
                except Exception as e: self.warn(name,'clean_output',repr(e),'left old directory')
        for name in GENERATED_FILES - {'.jxsi_cache.json'}:
            p = self.output/name
            if p.exists():
                try: p.unlink()
                except Exception as e: self.warn(name,'clean_output',repr(e),'left old file')

    def scan(self):
        started = time.time()
        self.output.mkdir(parents=True, exist_ok=True)
        self.load_cache()
        self.clean_output()
        self.log('SOURCE : %s' % self.source.resolve())
        self.log('OUTPUT : %s' % self.output.resolve())
        self.log('MODULES: %s' % (self.output/'MODULES').resolve())
        if is_subpath(self.output, self.source):
            self.log('Safety: Output nằm trong Source -> tự động loại Output khỏi quá trình quét.')

        recs=[]; tree=[str(self.source.resolve())]; ignored=[]; cache_hits=0; cache_misses=0
        self.log('1/10 Quét source', 2)
        out_resolved = self.output.resolve()
        for cr, dirs, files in os.walk(str(self.source)):
            self.cancelled()
            cur=Path(cr); rel_dir=cur.relative_to(self.source)
            filtered=[]
            for d in dirs:
                dp=(cur/d)
                if d.lower() in BUILD_DIR_NAMES:
                    continue
                try:
                    if is_subpath(dp, out_resolved) or dp.resolve() == out_resolved:
                        continue
                except Exception:
                    pass
                filtered.append(d)
            dirs[:] = filtered
            indent='    '*len(rel_dir.parts)
            if rel_dir.parts: tree.append('%s[DIR] %s/' % (indent, rel_dir.as_posix()))
            for fn in sorted(files):
                self.cancelled()
                p=cur/fn; rel=p.relative_to(self.source); rel_s=rel.as_posix(); tree.append('%s    %s' % (indent, fn)); ext=p.suffix.lower()
                if ext in BINARY_EXTENSIONS: ignored.append((rel_s,'binary/build/media')); continue
                if is_dep(rel) and not self.include_dep: ignored.append((rel_s,'dependency')); continue
                if ext not in TEXT_EXTENSIONS and not self.unknown_text: ignored.append((rel_s,'unsupported extension')); continue
                try:
                    st=p.stat(); size=st.st_size; mtime_ns=getattr(st,'st_mtime_ns',int(st.st_mtime*1e9))
                except Exception as e:
                    size=0; mtime_ns=0; self.warn(rel_s,'stat',repr(e))
                key=rel_s
                old=self.old_cache.get(key,{}) if self.incremental else {}
                text=enc=None; sha1=''
                if old and old.get('size')==size and old.get('mtime_ns')==mtime_ns and 'text' in old:
                    text=old.get('text'); enc=old.get('encoding'); sha1=old.get('sha1',''); cache_hits+=1
                else:
                    text,enc,err=safe_read_text(p)
                    if text is None:
                        ignored.append((rel_s,'unsupported/unreadable')); self.warn(rel_s,'read',err or 'unknown read error','ignored'); continue
                    sha1,err2=sha1_file(p)
                    if err2: self.warn(rel_s,'sha1',err2,'sha1 left blank')
                    cache_misses+=1
                self.new_cache[key]={'size':size,'mtime_ns':mtime_ns,'encoding':enc,'sha1':sha1,'text':text}
                recs.append({'path':p,'rel':rel,'rel_s':rel_s,'ext':ext,'size':size,'mtime_ns':mtime_ns,'encoding':enc,'module':classify_module(rel),'text':text,'sha1':sha1})
        (self.output/'00_SOURCE_TREE.txt').write_text('\n'.join(tree),encoding='utf-8')
        self.log('%d file text/source | cache hit %d | đọc lại %d' % (len(recs),cache_hits,cache_misses), 12)

        self.log('2/10 Symbol / include / script / project intelligence', 15)
        syms=[]; incs=[]; scripts=[]; projects=[]; function_ranges={}; file_symbols=defaultdict(list)
        for r in recs:
            self.cancelled()
            if r['ext'] in CPP_EXTENSIONS:
                xs=extract_symbols(r['text']); file_symbols[r['rel_s']]=[n for k,n,ln in xs]
                syms += [(n,k,r['module'],r['rel_s'],ln) for k,n,ln in xs]
                incs += [(r['module'],r['rel_s'],ln,i,style) for i,ln,style in extract_includes(r['text'])]
                # v3: scan script bindings in all C/C++ files, not only filenames containing lua/script.
                scripts += [(sn,cf,kind,r['module'],r['rel_s'],ln) for kind,sn,cf,ln in extract_script_bindings(r['text'])]
                if r['ext'] in SOURCE_EXTENSIONS:
                    function_ranges[r['rel_s']]=extract_function_ranges(r['text'])
            if r['ext'] in PROJECT_EXTENSIONS:
                projects.append({'file':r['rel_s'],'module':r['module'],**project_info(r['text'])})
        write_tsv(self.output/'01_FILE_MANIFEST.tsv',['relative_path','module','extension','size_bytes','encoding','sha1'],
                  [(r['rel_s'],r['module'],r['ext'],r['size'],r['encoding'],r['sha1']) for r in sorted(recs,key=lambda x:x['rel_s'].lower())])
        write_tsv(self.output/'02_SYMBOL_INDEX.tsv',['symbol','kind','module','file','line'],sorted(set(syms),key=lambda x:(x[0].lower(),x[3].lower(),x[4])))
        write_tsv(self.output/'03_INCLUDE_GRAPH.tsv',['module','file','line','include'],[(m,f,l,i) for m,f,l,i,s in sorted(set(incs),key=lambda x:(x[1].lower(),x[2]))])
        write_tsv(self.output/'04_SCRIPT_BINDING_CANDIDATES.tsv',['script_name','cpp_function','pattern','module','file','line'],sorted(set(scripts),key=lambda x:(x[0].lower(),x[4].lower(),x[5])))

        self.log('3/10 Win/Linux counterpart + source pairs', 25)
        linux=defaultdict(list)
        for r in recs:
            if r['rel'].parts and r['rel'].parts[0].lower()=='linux': linux[r['path'].name.lower()].append(r)
        cps=[]
        for w in recs:
            if w['rel'].parts and w['rel'].parts[0].lower()=='linux': continue
            for l in linux.get(w['path'].name.lower(),[]):
                score=1+len(set(p.lower() for p in w['rel'].parts[:-1]) & set(p.lower() for p in l['rel'].parts[:-1]))
                cps.append((w['rel_s'],l['rel_s'],w['path'].name,score))
        write_tsv(self.output/'05_WIN_LINUX_COUNTERPARTS.tsv',['win_file','linux_file','basename','heuristic_score'],sorted(set(cps),key=lambda x:(-x[3],x[2].lower(),x[0].lower())))
        by_stem=defaultdict(list)
        for r in recs:
            if r['ext'] in CPP_EXTENSIONS: by_stem[r['path'].stem.lower()].append(r)
        pairs=[]
        for stem,rs in by_stem.items():
            hs=[x for x in rs if x['ext'] in HEADER_EXTENSIONS]; cs=[x for x in rs if x['ext'] in SOURCE_EXTENSIONS]
            for h in hs:
                for c in cs:
                    score=2 if h['path'].parent==c['path'].parent else 1
                    pairs.append((stem,h['rel_s'],c['rel_s'],score))
        write_tsv(self.output/'12_SOURCE_PAIRS.tsv',['stem','header','source','heuristic_score'],sorted(set(pairs),key=lambda x:(x[0],-x[3],x[1],x[2])))

        self.log('4/10 Resolve includes + module dependencies', 34)
        rel_lookup={norm_rel(r['rel_s']):r for r in recs}; base_lookup=defaultdict(list)
        for r in recs: base_lookup[r['path'].name.lower()].append(r)
        resolved=[]; module_deps=Counter()
        for m,f,l,inc,style in incs:
            cur=next((x for x in recs if x['rel_s']==f),None)
            candidates=[]; inc_norm=norm_rel(inc)
            if cur:
                try:
                    q=(cur['path'].parent/inc).resolve().relative_to(self.source.resolve()).as_posix()
                    if norm_rel(q) in rel_lookup: candidates=[rel_lookup[norm_rel(q)]]
                except Exception: pass
            if not candidates:
                exact=[r for k,r in rel_lookup.items() if k.endswith('/'+inc_norm) or k==inc_norm]
                candidates=exact
            if not candidates:
                candidates=base_lookup.get(Path(inc).name.lower(),[])
            if len(candidates)==1:
                target=candidates[0]; status='RESOLVED'; resolved_file=target['rel_s']; target_module=target['module']
                if target_module != m: module_deps[(m,target_module)] += 1
            elif len(candidates)>1:
                status='AMBIGUOUS'; resolved_file=' | '.join(x['rel_s'] for x in candidates[:8]); target_module=''
            else:
                status='EXTERNAL_OR_MISSING'; resolved_file=''; target_module=''
            resolved.append((m,f,l,inc,style,status,resolved_file,target_module))
        write_tsv(self.output/'13_INCLUDE_RESOLVED.tsv',['module','file','line','include','style','status','resolved_file','target_module'],resolved)
        write_tsv(self.output/'14_MODULE_DEPENDENCIES.tsv',['source_module','target_module','resolved_include_count'],[(a,b,c) for (a,b),c in sorted(module_deps.items(), key=lambda x:(-x[1],x[0]))])

        self.log('5/10 Symbol references + heuristic call graph', 45)
        symbol_names=sorted(set(n for n,k,m,f,l in syms if len(n)>=3), key=lambda s:(-len(s),s.lower()))
        # Limit pathological regex size while keeping all meaningful legacy symbols.
        simple_names=defaultdict(set)
        for n in symbol_names:
            simple_names[n.split('::')[-1]].add(n)
        refs=[]; calls=[]
        token_rx=re.compile(r'\b[A-Za-z_]\w*(?:::[A-Za-z_]\w*)*\b')
        call_rx=re.compile(r'\b([A-Za-z_]\w*(?:::[A-Za-z_]\w*)*)\s*\(')
        symbol_set=set(symbol_names); simple_set=set(simple_names)
        for r in recs:
            self.cancelled()
            if r['ext'] not in CPP_EXTENSIONS: continue
            defs_by_line=defaultdict(set)
            for kind,n,ln in extract_symbols(r['text']): defs_by_line[ln].add(n)
            lines=r['text'].splitlines()
            for idx,line in enumerate(lines,1):
                if len(line)>20000: continue
                for tm in token_rx.finditer(line):
                    tok=tm.group(0)
                    matches=[]
                    if tok in symbol_set: matches=[tok]
                    elif tok in simple_set: matches=sorted(simple_names[tok])
                    if matches:
                        for target in matches[:8]:
                            if target in defs_by_line.get(idx,set()): continue
                            refs.append((target,r['module'],r['rel_s'],idx,line.strip()[:240]))
            for fname,start,end,startln,endln in function_ranges.get(r['rel_s'],[]):
                body=r['text'][start:end]
                for cm in call_rx.finditer(body):
                    callee=cm.group(1); simple=callee.split('::')[-1]
                    if simple.lower() in STOP_CALLS or callee==fname or simple==fname.split('::')[-1]: continue
                    resolved_name=''
                    if callee in symbol_set: resolved_name=callee
                    elif simple in simple_set and len(simple_names[simple])==1: resolved_name=next(iter(simple_names[simple]))
                    elif simple in simple_set: resolved_name='AMBIGUOUS:'+'|'.join(sorted(simple_names[simple])[:6])
                    else: continue
                    calls.append((fname,resolved_name,r['module'],r['rel_s'],startln+body[:cm.start()].count('\n'),callee))
        # Deduplicate aggressively; reference index remains navigation-oriented rather than compiler-perfect.
        refs=sorted(set(refs), key=lambda x:(x[0].lower(),x[2].lower(),x[3]))
        calls=sorted(set(calls), key=lambda x:(x[0].lower(),x[3].lower(),x[4],x[1].lower()))
        write_tsv(self.output/'10_SYMBOL_REFERENCES.tsv',['symbol','module','file','line','context'],refs)
        write_tsv(self.output/'11_CALL_GRAPH.tsv',['caller','callee_resolved','module','file','line','callee_token'],calls)

        self.log('6/10 Project/build configuration intelligence', 58)
        (self.output/'06_PROJECT_MAP.json').write_text(json.dumps(projects,ensure_ascii=False,indent=2),encoding='utf-8')
        md=['# PROJECT / WORKSPACE MAP\n\n']
        build_rows=[]
        for p in projects:
            md.append("## %s\n\n- Module: `%s`\n" % (p['file'],p['module']))
            if p['projects']:
                md.append('- Projects:\n'); md.extend("  - `%s` → `%s`\n" % (x['name'],x['definition']) for x in p['projects'])
            if p['dependencies']: md.append('- Dependencies: '+', '.join('`'+x+'`' for x in sorted(set(p['dependencies'])))+'\n')
            if p['outputs']: md.append('- Outputs: '+', '.join('`'+x+'`' for x in sorted(set(p['outputs'])))+'\n')
            if p['build_configs']:
                md.append('- Build configurations:\n')
                for c in p['build_configs']:
                    md.append('  - `%s`\n' % c['configuration'])
                    build_rows.append((p['file'],p['module'],c['configuration'],';'.join(c['defines']),';'.join(c['include_paths']),';'.join(c['libraries']),';'.join(c['lib_paths']),';'.join(c['outputs'])))
            md.append('\n')
        (self.output/'06_PROJECT_MAP.md').write_text(''.join(md),encoding='utf-8')
        write_tsv(self.output/'15_BUILD_CONFIGS.tsv',['project_file','module','configuration','defines','include_paths','libraries','lib_paths','outputs'],build_rows)

        self.log('7/10 Subsystem map + script API map', 66)
        subsystem_rows=[]; subsystem_files=defaultdict(list)
        for r in recs:
            ss=classify_subsystem(r['rel_s'],file_symbols.get(r['rel_s']))
            r['subsystem']=ss; subsystem_files[ss].append(r)
            subsystem_rows.append((ss,r['module'],r['rel_s'],','.join(file_symbols.get(r['rel_s'],[])[:30])))
        write_tsv(self.output/'16_SUBSYSTEM_MAP.tsv',['subsystem','module','file','symbols_sample'],sorted(subsystem_rows,key=lambda x:(x[0],x[1],x[2])))
        script_rows=[]
        sym_def=defaultdict(list)
        for n,k,m,f,l in syms: sym_def[n].append((m,f,l,k))
        for sn,cf,kind,m,f,l in scripts:
            defs=sym_def.get(cf,[]) or sym_def.get(cf.split('::')[-1],[])
            if defs:
                for dm,df,dl,dk in defs: script_rows.append((sn,cf,kind,m,f,l,'RESOLVED',dm,df,dl))
            else: script_rows.append((sn,cf,kind,m,f,l,'UNRESOLVED','','',''))
        write_tsv(self.output/'17_SCRIPT_API_MAP.tsv',['script_name','cpp_function','pattern','binding_module','binding_file','binding_line','status','definition_module','definition_file','definition_line'],script_rows)

        self.log('8/10 Source diff + feature entry points', 73)
        old_keys=set(self.old_cache); new_keys=set(self.new_cache); diff=[]
        for k in sorted(new_keys-old_keys): diff.append(('ADDED',k,'',''))
        for k in sorted(old_keys-new_keys): diff.append(('DELETED',k,self.old_cache[k].get('sha1',''),''))
        for k in sorted(new_keys & old_keys):
            o=self.old_cache[k]; n=self.new_cache[k]
            if o.get('sha1') != n.get('sha1'):
                diff.append(('MODIFIED',k,o.get('sha1',''),n.get('sha1','')))
        write_tsv(self.output/'09_SOURCE_DIFF.tsv',['change','relative_path','old_sha1','new_sha1'],diff)
        diff_md=['# SOURCE DIFF\n\n','Compared against previous scanner cache.\n\n']
        if not self.old_cache: diff_md.append('No previous cache was available; all current files are treated as ADDED.\n')
        for change in ('ADDED','MODIFIED','DELETED'):
            rows=[x for x in diff if x[0]==change]; diff_md.append('\n## %s (%d)\n\n' % (change,len(rows)))
            diff_md.extend('- `%s`\n' % x[1] for x in rows[:2000])
        (self.output/'09_SOURCE_DIFF.md').write_text(''.join(diff_md),encoding='utf-8')
        # Generic entry points for common feature families: strongest symbols/files per subsystem.
        ref_count=Counter(x[0] for x in refs); call_count=Counter(x[0] for x in calls)
        entry=[]
        for ss,rs in subsystem_files.items():
            candidates=[]
            for r in rs:
                for n in file_symbols.get(r['rel_s'],[]):
                    candidates.append((ref_count[n]+call_count[n],n,r['module'],r['rel_s']))
            for score,n,m,f in sorted(set(candidates),reverse=True)[:40]: entry.append((ss,n,m,f,score))
        write_tsv(self.output/'18_FEATURE_ENTRY_POINTS.tsv',['subsystem','symbol','module','file','reference_call_score'],sorted(entry,key=lambda x:(x[0],-x[4],x[1].lower())))

        self.log('9/10 Module packages + AI packs', 82)
        modules=defaultdict(list)
        for r in recs: modules[r['module']].append(r)
        root=self.output/'MODULES'; root.mkdir(exist_ok=True); pkg=[]
        for m in sorted(modules,key=str.lower):
            d=root/Path(*[clean_name(x) for x in m.split('/')]); d.mkdir(parents=True,exist_ok=True)
            part=1; cur=[]; cb=0; cnt=0
            def flush_module():
                nonlocal part,cur,cb,cnt
                if not cur: return
                fp=d/('part_%03d.md'%part)
                fp.write_text('# MODULE: %s\n# PART: %03d\n# FILE COUNT: %d\n\n%s' % (m,part,cnt,''.join(cur)),encoding='utf-8')
                pkg.append((m,fp.relative_to(self.output).as_posix(),cnt,cb)); part+=1;cur=[];cb=0;cnt=0
            for r in sorted(modules[m],key=lambda x:x['rel_s'].lower()):
                block='\n\n'+'='*100+'\nFILE: %s\nMODULE: %s\nSUBSYSTEM: %s\nENCODING: %s\n' % (r['rel_s'],r['module'],r.get('subsystem',''),r['encoding'])+'='*100+'\n\n```text\n'+r['text']+('' if r['text'].endswith('\n') else '\n')+'```\n'
                b=len(block.encode('utf-8'))
                if cur and cb+b>self.max_bytes: flush_module()
                cur.append(block);cb+=b;cnt+=1
            flush_module()
        write_tsv(self.output/'07_MODULE_PACKAGE_INDEX.tsv',['module','package','files','bytes'],pkg)

        ai_pack_index=[]
        if self.ai_packs:
            airoot=self.output/'AI_PACKS'; airoot.mkdir(exist_ok=True)
            for ss in sorted(subsystem_files):
                if ss=='OTHER': continue
                rs=sorted(subsystem_files[ss],key=lambda x:(x['module'].lower(),x['rel_s'].lower()))
                d=airoot/clean_name(ss); d.mkdir(exist_ok=True)
                # Map file first: navigation only, intentionally compact.
                mm=['# AI PACK: %s\n\n' % ss,'## Relevant files\n\n']
                for r in rs[:2000]: mm.append('- `%s` — module `%s`\n' % (r['rel_s'],r['module']))
                mm.append('\n## Suggested entry points\n\n')
                for row in [x for x in entry if x[0]==ss][:80]: mm.append('- `%s` → `%s` (score %s)\n' % (row[1],row[3],row[4]))
                (d/'00_MAP.md').write_text(''.join(mm),encoding='utf-8')
                part=1;cur=[];cb=0;cnt=0
                def flush_ai():
                    nonlocal part,cur,cb,cnt
                    if not cur:return
                    fp=d/('part_%03d.md'%part); fp.write_text('# AI PACK: %s\n# PART: %03d\n# FILE COUNT: %d\n\n%s' % (ss,part,cnt,''.join(cur)),encoding='utf-8')
                    ai_pack_index.append((ss,fp.relative_to(self.output).as_posix(),cnt,cb)); part+=1;cur=[];cb=0;cnt=0
                for r in rs:
                    block='\n\n'+'='*100+'\nFILE: %s\nMODULE: %s\nSUBSYSTEM: %s\nENCODING: %s\n' % (r['rel_s'],r['module'],ss,r['encoding'])+'='*100+'\n\n```text\n'+r['text']+('' if r['text'].endswith('\n') else '\n')+'```\n'
                    b=len(block.encode('utf-8'))
                    if cur and cb+b>self.max_bytes: flush_ai()
                    cur.append(block);cb+=b;cnt+=1
                flush_ai()
        write_tsv(self.output/'19_AI_PACK_INDEX.tsv',['subsystem','package','files','bytes'],ai_pack_index)

        self.log('10/10 AI bootstrap / guide / stats', 93)
        stats={'version':VERSION,'scan_time':datetime.now().isoformat(timespec='seconds'),'source_root':str(self.source.resolve()),'output_root':str(self.output.resolve()),'text_files':len(recs),'modules':{k:len(v) for k,v in modules.items()},'subsystems':{k:len(v) for k,v in subsystem_files.items()},'symbols':len(syms),'symbol_references':len(refs),'call_edges':len(calls),'includes':len(incs),'resolved_includes':sum(1 for x in resolved if x[5]=='RESOLVED'),'script_binding_candidates':len(scripts),'win_linux_counterparts':len(cps),'project_files':len(projects),'include_dependencies':self.include_dep,'max_package_bytes':self.max_bytes,'cache_hits':cache_hits,'cache_misses':cache_misses,'source_diff':dict(Counter(x[0] for x in diff)),'warnings':len(self.warnings),'elapsed_seconds':round(time.time()-started,2)}
        (self.output/'08_STATS.json').write_text(json.dumps(stats,ensure_ascii=False,indent=2),encoding='utf-8')

        bootstrap=['# AI BOOTSTRAP — JX SOURCE INTELLIGENCE v3\n\n',
                   'This file is the first navigation context for an AI working on this source tree.\n\n',
                   '## Source\n\n- Root: `%s`\n- Scanner: `%s`\n- Text/source files: **%d**\n- Modules: **%d**\n- Symbols: **%d**\n- Symbol references: **%d**\n- Call edges (heuristic): **%d**\n\n' % (self.source.resolve(),VERSION,len(recs),len(modules),len(syms),len(refs),len(calls)),
                   '## Main modules\n\n']
        for m,c in sorted(((k,len(v)) for k,v in modules.items()),key=lambda x:(-x[1],x[0].lower())): bootstrap.append('- `%s`: %d files\n' % (m,c))
        bootstrap.append('\n## Detected subsystems\n\n')
        for s,c in sorted(((k,len(v)) for k,v in subsystem_files.items()),key=lambda x:(-x[1],x[0])): bootstrap.append('- `%s`: %d files\n' % (s,c))
        bootstrap += ['\n## Intelligence indexes\n\n',
                      '- `02_SYMBOL_INDEX.tsv` — definitions/declarations detected heuristically.\n',
                      '- `10_SYMBOL_REFERENCES.tsv` — navigation-oriented symbol usages.\n',
                      '- `11_CALL_GRAPH.tsv` — heuristic caller → callee edges.\n',
                      '- `13_INCLUDE_RESOLVED.tsv` — include resolution with RESOLVED/AMBIGUOUS/EXTERNAL_OR_MISSING.\n',
                      '- `14_MODULE_DEPENDENCIES.tsv` — module dependency counts from resolved includes.\n',
                      '- `15_BUILD_CONFIGS.tsv` — project configurations/defines/includes/libs/outputs.\n',
                      '- `16_SUBSYSTEM_MAP.tsv` — files grouped by AI-oriented subsystem.\n',
                      '- `17_SCRIPT_API_MAP.tsv` — script binding → C/C++ definition map.\n',
                      '- `18_FEATURE_ENTRY_POINTS.tsv` — likely starting symbols per subsystem.\n',
                      '- `MODULES/` — full source packages by physical module.\n',
                      '- `AI_PACKS/` — cross-module source packages by subsystem.\n\n',
                      '## Recommended AI investigation workflow\n\n',
                      '1. Read `AI_BOOTSTRAP.md`, `08_STATS.json`, and `06_PROJECT_MAP.md`.\n',
                      '2. Map the requested feature with `16_SUBSYSTEM_MAP.tsv` and `18_FEATURE_ENTRY_POINTS.tsv`.\n',
                      '3. Locate definitions in `02_SYMBOL_INDEX.tsv`.\n',
                      '4. Follow usages in `10_SYMBOL_REFERENCES.tsv` and caller/callee edges in `11_CALL_GRAPH.tsv`.\n',
                      '5. Check `13_INCLUDE_RESOLVED.tsv`, `14_MODULE_DEPENDENCIES.tsv`, and `15_BUILD_CONFIGS.tsv` before proposing build changes.\n',
                      '6. Read the relevant `AI_PACKS/<SUBSYSTEM>/00_MAP.md`, then only the needed source package parts.\n',
                      '7. Treat call/reference/include resolution as heuristic navigation; verify critical behavior against packaged source before editing.\n']
        (self.output/'AI_BOOTSTRAP.md').write_text(''.join(bootstrap),encoding='utf-8')

        guide=['# AI SOURCE GUIDE\n\n','## What v3 preserves\n\nAll v2 indexes and MODULES packaging remain available. v3 adds cross-reference, build, subsystem and AI navigation indexes.\n\n',
               '## When implementing a new feature\n\n','Start with `AI_BOOTSTRAP.md`. Then identify the subsystem, inspect entry points, follow symbols/references/calls/includes, verify the target build configuration, and finally read exact source from `AI_PACKS` or `MODULES`.\n\n',
               '## Accuracy note\n\n','This scanner uses static regex/heuristic analysis so it can work on legacy VC6-era C/C++ without requiring a compiler database. Indexes accelerate navigation but do not replace verification against source code.\n']
        (self.output/'20_AI_SOURCE_GUIDE.md').write_text(''.join(guide),encoding='utf-8')

        preferred=['Core','Engine','MultiServer/GameServer','MultiServer/S3Relay','MultiServer/Bishop','MultiServer/Goddess','MultiServer/Heaven','MultiServer/Rainbow','S3Client','Network/ESClient','Kernel/Core','Kernel/Engine','LINUX/Core','LINUX/Engine','LINUX/lua','LINUX']
        order=['# AI READ ORDER — JX SOURCE INTELLIGENCE v3\n\n','## Gửi trước\n\n1. `AI_BOOTSTRAP.md`\n2. `08_STATS.json`\n3. `06_PROJECT_MAP.md`\n4. `16_SUBSYSTEM_MAP.tsv`\n5. `18_FEATURE_ENTRY_POINTS.tsv`\n6. `15_BUILD_CONFIGS.tsv`\n7. `02_SYMBOL_INDEX.tsv`\n\n','## Khi điều tra một tính năng\n\nDùng `10_SYMBOL_REFERENCES.tsv`, `11_CALL_GRAPH.tsv`, `13_INCLUDE_RESOLVED.tsv`, `14_MODULE_DEPENDENCIES.tsv`, sau đó đọc `AI_PACKS/<SUBSYSTEM>/00_MAP.md` và các part cần thiết.\n\n','## Module ưu tiên\n\n']
        for m in preferred:
            if m in modules:
                order.append('### %s\n' % m)
                for mm,p,c,b in pkg:
                    if mm==m: order.append('- `%s` (%d files)\n' % (p,c))
                order.append('\n')
        order.append('## Khi cần đọc script Linux rồi viết lại cho JX Win\n\nCung cấp script Linux cần xử lý + `17_SCRIPT_API_MAP.tsv` + module/API liên quan. Mục tiêu là hiểu hành vi, tìm binding/API tương đương trong JX Win và viết lại theo JX Win, không dịch máy từng dòng.\n')
        (self.output/'AI_READ_ORDER.md').write_text(''.join(order),encoding='utf-8')

        write_tsv(self.output/'98_SCAN_WARNINGS.tsv',['file','stage','error','action'],self.warnings)
        with (self.output/'99_IGNORED_FILES.txt').open('w',encoding='utf-8') as f:
            for rel,why in ignored: f.write('[%s] %s\n' % (why,rel))
        # Cache last, after all analysis succeeds.
        try: self.cache_path.write_text(json.dumps(self.new_cache,ensure_ascii=False),encoding='utf-8')
        except Exception as e: self.warn('.jxsi_cache.json','save_cache',repr(e),'cache not saved')
        starter=['AI_BOOTSTRAP.md','AI_READ_ORDER.md','08_STATS.json','06_PROJECT_MAP.md','16_SUBSYSTEM_MAP.tsv','18_FEATURE_ENTRY_POINTS.tsv','15_BUILD_CONFIGS.tsv','02_SYMBOL_INDEX.tsv','20_AI_SOURCE_GUIDE.md']
        copied=build_chatgpt_uploaded(self.output,starter,'CHATGPT FIRST-UPLOAD BUNDLE — C/C++ SOURCE',[
            'Start with these compact navigation files before uploading large MODULES or AI_PACKS parts.',
            'When ChatGPT asks for exact code, upload only the requested package from the parent output folder.'
        ])
        self.log('CHATGPT_UPLOADED: %d file khởi tạo AI' % len(copied))
        self.log('Hoàn tất trong %.2f giây' % (time.time()-started),100)
        return stats


class LuaScanner:
    def __init__(self, source, output, max_bytes, incremental, clean_generated, cancel_event, emit):
        self.source=source; self.output=output; self.max_bytes=max_bytes
        self.incremental=incremental; self.clean_generated=clean_generated
        self.cancel_event=cancel_event; self.emit=emit; self.warnings=[]
        self.cache_path=output/'.jxsi_lua_cache.json'; self.old_cache={}; self.new_cache={}

    def cancelled(self):
        if self.cancel_event.is_set(): raise RuntimeError('__CANCELLED__')
    def log(self,msg,progress=None): self.emit(('log',msg,progress))
    def warn(self,rel,stage,err,action='continued'): self.warnings.append((rel,stage,err,action))
    def clean_output(self):
        if not self.clean_generated:return
        for name in ('LUA_MODULES','AI_PACKS','CHATGPT_UPLOADED'):
            p=self.output/name
            if p.exists():
                try: shutil.rmtree(str(p))
                except Exception as e:self.warn(name,'clean_output',repr(e),'left old directory')
        for p in self.output.glob('*'):
            if p.is_file() and (p.name.startswith(('00_','01_','02_','03_','04_','05_','06_','07_','08_','09_','10_','11_','12_','13_','14_','98_','99_','AI_'))):
                try:p.unlink()
                except Exception as e:self.warn(p.name,'clean_output',repr(e),'left old file')
    def load_cache(self):
        if self.incremental and self.cache_path.exists():
            try:self.old_cache=json.loads(self.cache_path.read_text(encoding='utf-8'))
            except Exception as e:self.warn(self.cache_path.name,'load_cache',repr(e),'ignored cache')

    def scan(self):
        started=time.time(); self.output.mkdir(parents=True,exist_ok=True); self.load_cache(); self.clean_output()
        self.log('LUA SOURCE : %s' % self.source.resolve())
        self.log('LUA OUTPUT : %s' % self.output.resolve())
        if is_subpath(self.output,self.source): self.log('Safety: Output nằm trong Lua Source -> tự động loại Output khỏi scan.')
        tree=[str(self.source.resolve())]; recs=[]; ignored=[]; hits=0; misses=0
        out_resolved=self.output.resolve(); self.log('1/8 Quét Lua scripts',5)
        for cr,dirs,files in os.walk(str(self.source)):
            self.cancelled(); cur=Path(cr); rel_dir=cur.relative_to(self.source)
            filtered=[]
            for d in dirs:
                dp=cur/d
                if d.lower() in BUILD_DIR_NAMES:continue
                try:
                    if is_subpath(dp,out_resolved) or dp.resolve()==out_resolved:continue
                except Exception:pass
                filtered.append(d)
            dirs[:]=filtered; indent='    '*len(rel_dir.parts)
            if rel_dir.parts:tree.append('%s[DIR] %s/'%(indent,rel_dir.as_posix()))
            for fn in sorted(files):
                p=cur/fn; rel=p.relative_to(self.source); rel_s=rel.as_posix(); tree.append('%s    %s'%(indent,fn))
                if p.suffix.lower()!='.lua': ignored.append((rel_s,'not lua')); continue
                try:
                    st=p.stat(); size=st.st_size; mt=getattr(st,'st_mtime_ns',int(st.st_mtime*1e9))
                except Exception as e:size=0;mt=0;self.warn(rel_s,'stat',repr(e))
                old=self.old_cache.get(rel_s,{}) if self.incremental else {}; text=enc=None;sha1=''
                if old and old.get('size')==size and old.get('mtime_ns')==mt and 'text' in old:
                    text=old['text'];enc=old.get('encoding');sha1=old.get('sha1','');hits+=1
                else:
                    text,enc,err=safe_read_text(p)
                    if text is None:self.warn(rel_s,'read',err or 'read failed','ignored');ignored.append((rel_s,'unreadable'));continue
                    sha1,err2=sha1_file(p); misses+=1
                    if err2:self.warn(rel_s,'sha1',err2,'blank sha1')
                self.new_cache[rel_s]={'size':size,'mtime_ns':mt,'encoding':enc,'sha1':sha1,'text':text}
                recs.append({'path':p,'rel':rel,'rel_s':rel_s,'size':size,'encoding':enc,'sha1':sha1,'text':text,'module':classify_lua_module(rel)})
        (self.output/'00_LUA_SOURCE_TREE.txt').write_text('\\n'.join(tree),encoding='utf-8')
        self.log('%d Lua files | cache hit %d | đọc lại %d'%(len(recs),hits,misses),15)

        self.log('2/8 Function / global / dependency indexes',25)
        funcs=[]; globals_=[]; reqs=[]; calls=[]; by_file_funcs=defaultdict(list)
        for r in recs:
            self.cancelled(); fs=extract_lua_functions(r['text']); by_file_funcs[r['rel_s']]=[n for k,n,l in fs]
            funcs += [(n,k,r['module'],r['rel_s'],l) for k,n,l in fs]
            globals_ += [(n,r['module'],r['rel_s'],l) for n,l in extract_lua_globals(r['text'])]
            reqs += [(kind,target,r['module'],r['rel_s'],l) for kind,target,l in extract_lua_requires(r['text'])]
            calls += [(n,r['module'],r['rel_s'],l) for n,l in extract_lua_calls(r['text'])]
        write_tsv(self.output/'01_LUA_FILE_MANIFEST.tsv',['relative_path','module','size_bytes','encoding','sha1'],[(r['rel_s'],r['module'],r['size'],r['encoding'],r['sha1']) for r in recs])
        write_tsv(self.output/'02_LUA_FUNCTION_INDEX.tsv',['function','kind','module','file','line'],sorted(set(funcs),key=lambda x:(x[0].lower(),x[3],x[4])))
        write_tsv(self.output/'03_LUA_GLOBAL_INDEX.tsv',['global','module','file','line'],sorted(set(globals_),key=lambda x:(x[0].lower(),x[2],x[3])))
        write_tsv(self.output/'04_LUA_DEPENDENCIES.tsv',['kind','target','module','file','line'],sorted(set(reqs),key=lambda x:(x[3],x[4])))
        write_tsv(self.output/'05_LUA_CALLS.tsv',['callee','module','file','line'],sorted(set(calls),key=lambda x:(x[0].lower(),x[2],x[3])))

        self.log('3/8 Resolve Lua dependencies',38)
        stem_lookup=defaultdict(list); rel_lookup={norm_rel(r['rel_s']):r for r in recs}
        for r in recs:stem_lookup[r['path'].stem.lower()].append(r)
        resolved=[]; dep_counter=Counter()
        for kind,target,m,f,l in reqs:
            t=target.replace('.','/') if kind=='require' else target.replace('\\\\','/')
            candidates=[]
            for cand in (t,t+'.lua',t+'/init.lua'):
                n=norm_rel(cand)
                if n in rel_lookup:candidates=[rel_lookup[n]];break
                xs=[r for k,r in rel_lookup.items() if k.endswith('/'+n)]
                if xs:candidates=xs;break
            if not candidates:candidates=stem_lookup.get(Path(t).stem.lower(),[])
            if len(candidates)==1:
                rr=candidates[0]; status='RESOLVED'; rf=rr['rel_s']; tm=rr['module']; dep_counter[(m,tm)]+=1
            elif len(candidates)>1:status='AMBIGUOUS';rf=' | '.join(x['rel_s'] for x in candidates[:8]);tm=''
            else:status='EXTERNAL_OR_MISSING';rf='';tm=''
            resolved.append((kind,target,m,f,l,status,rf,tm))
        write_tsv(self.output/'06_LUA_DEPENDENCIES_RESOLVED.tsv',['kind','target','module','file','line','status','resolved_file','target_module'],resolved)
        write_tsv(self.output/'07_LUA_MODULE_DEPENDENCIES.tsv',['source_module','target_module','count'],[(a,b,c) for (a,b),c in sorted(dep_counter.items(),key=lambda x:(-x[1],x[0]))])

        self.log('4/8 References + entry points',52)
        def_names=set(n for n,k,m,f,l in funcs); refs=[]
        for n,m,f,l in calls:
            if n in def_names:refs.append((n,m,f,l,'call'))
            else:
                tail=n.split('.')[-1].split(':')[-1]
                matches=[x for x in def_names if x.split('.')[-1].split(':')[-1]==tail]
                if len(matches)==1:refs.append((matches[0],m,f,l,'tail-match'))
        write_tsv(self.output/'08_LUA_FUNCTION_REFERENCES.tsv',['function','module','file','line','match'],sorted(set(refs),key=lambda x:(x[0].lower(),x[2],x[3])))
        subsystem_files=defaultdict(list)
        for r in recs:
            ss=classify_subsystem(r['rel_s'],by_file_funcs.get(r['rel_s'],[])); r['subsystem']=ss; subsystem_files[ss].append(r)
        write_tsv(self.output/'09_LUA_SUBSYSTEM_MAP.tsv',['subsystem','module','file','functions'],[(r['subsystem'],r['module'],r['rel_s'],';'.join(by_file_funcs.get(r['rel_s'],[])[:100])) for r in recs])
        scores=Counter()
        for n,k,m,f,l in funcs:scores[(n,m,f)]+=2
        for n,m,f,l,mt in refs:scores[(n,m,f)]+=1
        entries=[]
        for ss,rs in subsystem_files.items():
            fileset=set(r['rel_s'] for r in rs); cand=[(score,n,m,f) for (n,m,f),score in scores.items() if f in fileset]
            for score,n,m,f in sorted(cand,reverse=True)[:50]:entries.append((ss,n,m,f,score))
        write_tsv(self.output/'10_LUA_FEATURE_ENTRY_POINTS.tsv',['subsystem','function','module','file','score'],sorted(entries,key=lambda x:(x[0],-x[4],x[1].lower())))

        self.log('5/8 Lua packages',66)
        modules=defaultdict(list)
        for r in recs:modules[r['module']].append(r)
        root=self.output/'LUA_MODULES';root.mkdir(exist_ok=True); pkg=[]
        for m in sorted(modules,key=str.lower):
            d=root/Path(*[clean_name(x) for x in m.split('/')]);d.mkdir(parents=True,exist_ok=True);part=1;cur=[];cb=0;cnt=0
            def flush():
                nonlocal part,cur,cb,cnt
                if not cur:return
                fp=d/('part_%03d.md'%part);fp.write_text('# LUA MODULE: %s\\n# PART: %03d\\n# FILE COUNT: %d\\n\\n%s'%(m,part,cnt,''.join(cur)),encoding='utf-8');pkg.append((m,fp.relative_to(self.output).as_posix(),cnt,cb));part+=1;cur=[];cb=0;cnt=0
            for r in sorted(modules[m],key=lambda x:x['rel_s'].lower()):
                block='\\n\\n'+'='*100+'\\nFILE: %s\\nMODULE: %s\\nSUBSYSTEM: %s\\nENCODING: %s\\n'%(r['rel_s'],r['module'],r['subsystem'],r['encoding'])+'='*100+'\\n\\n```lua\\n'+r['text']+('' if r['text'].endswith('\\n') else '\\n')+'```\\n';b=len(block.encode('utf-8'))
                if cur and cb+b>self.max_bytes:flush()
                cur.append(block);cb+=b;cnt+=1
            flush()
        write_tsv(self.output/'11_LUA_PACKAGE_INDEX.tsv',['module','package','files','bytes'],pkg)

        self.log('6/8 AI packs',76)
        airoot=self.output/'AI_PACKS';airoot.mkdir(exist_ok=True); aip=[]
        for ss,rs in sorted(subsystem_files.items()):
            if ss=='OTHER':continue
            d=airoot/clean_name(ss);d.mkdir(exist_ok=True)
            mm=['# LUA AI PACK: %s\\n\\n## Relevant files\\n\\n'%ss]+['- `%s` — `%s`\\n'%(r['rel_s'],r['module']) for r in sorted(rs,key=lambda x:x['rel_s'])]
            mm.append('\\n## Suggested entry points\\n\\n')
            for row in [x for x in entries if x[0]==ss][:80]:mm.append('- `%s` → `%s` (score %s)\\n'%(row[1],row[3],row[4]))
            (d/'00_MAP.md').write_text(''.join(mm),encoding='utf-8')
            part=1;cur=[];cb=0;cnt=0
            def flush_ai():
                nonlocal part,cur,cb,cnt
                if not cur:return
                fp=d/('part_%03d.md'%part);fp.write_text('# LUA AI PACK: %s\\n# PART: %03d\\n# FILE COUNT: %d\\n\\n%s'%(ss,part,cnt,''.join(cur)),encoding='utf-8');aip.append((ss,fp.relative_to(self.output).as_posix(),cnt,cb));part+=1;cur=[];cb=0;cnt=0
            for r in sorted(rs,key=lambda x:x['rel_s']):
                block='\\n\\n'+'='*100+'\\nFILE: %s\\nMODULE: %s\\nSUBSYSTEM: %s\\n'%(r['rel_s'],r['module'],ss)+'='*100+'\\n\\n```lua\\n'+r['text']+('' if r['text'].endswith('\\n') else '\\n')+'```\\n';b=len(block.encode('utf-8'))
                if cur and cb+b>self.max_bytes:flush_ai()
                cur.append(block);cb+=b;cnt+=1
            flush_ai()
        write_tsv(self.output/'12_LUA_AI_PACK_INDEX.tsv',['subsystem','package','files','bytes'],aip)

        self.log('7/8 AI bootstrap / stats',88)
        stats={'version':VERSION,'language':'Lua','scan_time':datetime.now().isoformat(timespec='seconds'),'source_root':str(self.source.resolve()),'output_root':str(self.output.resolve()),'lua_files':len(recs),'modules':{k:len(v) for k,v in modules.items()},'subsystems':{k:len(v) for k,v in subsystem_files.items()},'functions':len(funcs),'globals':len(globals_),'dependencies':len(reqs),'resolved_dependencies':sum(1 for x in resolved if x[5]=='RESOLVED'),'function_references':len(refs),'cache_hits':hits,'cache_misses':misses,'warnings':len(self.warnings)}
        (self.output/'13_LUA_STATS.json').write_text(json.dumps(stats,ensure_ascii=False,indent=2),encoding='utf-8')
        boot=['# AI BOOTSTRAP — JX LUA SCRIPT INTELLIGENCE v%s\\n\\n'%VERSION,'Use this file as the first context when ChatGPT must understand or modify the Lua script tree.\\n\\n','## Source\\n\\n- Root: `%s`\\n- Lua files: **%d**\\n- Functions: **%d**\\n- Function references: **%d**\\n- Modules: **%d**\\n\\n'%(self.source.resolve(),len(recs),len(funcs),len(refs),len(modules)),'## Recommended workflow\\n\\n1. Read `AI_LUA_BOOTSTRAP.md` and `13_LUA_STATS.json`.\\n2. Use `09_LUA_SUBSYSTEM_MAP.tsv` and `10_LUA_FEATURE_ENTRY_POINTS.tsv` to find the feature area.\\n3. Use `02_LUA_FUNCTION_INDEX.tsv`, `08_LUA_FUNCTION_REFERENCES.tsv`, and `05_LUA_CALLS.tsv` to trace behavior.\\n4. Check `06_LUA_DEPENDENCIES_RESOLVED.tsv` before changing file/module relationships.\\n5. Read exact code from `AI_PACKS/<SUBSYSTEM>/` or `LUA_MODULES/`.\\n6. Treat heuristic indexes as navigation aids and verify critical behavior against packaged Lua source.\\n\\n','## Detected subsystems\\n\\n']
        for ss,c in sorted(((k,len(v)) for k,v in subsystem_files.items()),key=lambda x:(-x[1],x[0])):boot.append('- `%s`: %d files\\n'%(ss,c))
        (self.output/'AI_LUA_BOOTSTRAP.md').write_text(''.join(boot),encoding='utf-8')
        order=['# AI READ ORDER — LUA\\n\\n## Upload first\\n\\n1. `AI_LUA_BOOTSTRAP.md`\\n2. `13_LUA_STATS.json`\\n3. `09_LUA_SUBSYSTEM_MAP.tsv`\\n4. `10_LUA_FEATURE_ENTRY_POINTS.tsv`\\n5. `02_LUA_FUNCTION_INDEX.tsv`\\n6. `06_LUA_DEPENDENCIES_RESOLVED.tsv`\\n7. `08_LUA_FUNCTION_REFERENCES.tsv`\\n\\nThen upload only requested code from `AI_PACKS` or `LUA_MODULES`.\\n']
        (self.output/'AI_LUA_READ_ORDER.md').write_text(''.join(order),encoding='utf-8')
        (self.output/'14_LUA_AI_GUIDE.md').write_text('# LUA AI SOURCE GUIDE\\n\\nThis output is optimized for AI-first navigation of JX Lua scripts: subsystem → entry point → function → references/calls → dependencies → exact packaged source.\\n',encoding='utf-8')
        write_tsv(self.output/'98_LUA_SCAN_WARNINGS.tsv',['file','stage','error','action'],self.warnings)
        with (self.output/'99_LUA_IGNORED_FILES.txt').open('w',encoding='utf-8') as f:
            for rel,why in ignored:f.write('[%s] %s\\n'%(why,rel))
        try:self.cache_path.write_text(json.dumps(self.new_cache,ensure_ascii=False),encoding='utf-8')
        except Exception as e:self.warn(self.cache_path.name,'save_cache',repr(e),'cache not saved')

        self.log('8/8 CHATGPT_UPLOADED',95)
        starter=['AI_LUA_BOOTSTRAP.md','AI_LUA_READ_ORDER.md','13_LUA_STATS.json','09_LUA_SUBSYSTEM_MAP.tsv','10_LUA_FEATURE_ENTRY_POINTS.tsv','02_LUA_FUNCTION_INDEX.tsv','06_LUA_DEPENDENCIES_RESOLVED.tsv','08_LUA_FUNCTION_REFERENCES.tsv','14_LUA_AI_GUIDE.md']
        copied=build_chatgpt_uploaded(self.output,starter,'CHATGPT FIRST-UPLOAD BUNDLE — LUA SCRIPT',[
            'Upload this folder first when asking ChatGPT to understand or modify the Lua system.',
            'Large Lua code packages remain in the parent LUA_MODULES and AI_PACKS folders.'
        ])
        self.log('CHATGPT_UPLOADED: %d file khởi tạo AI'%len(copied))
        self.log('Hoàn tất Lua scan trong %.2f giây'%(time.time()-started),100)
        return stats




CLIENT_SUBSYSTEM_RULES = [
    ('GRAPHICS', ('graphics','video','display','resolution','width','height','window','fullscreen','render','represent','d3d','texture','gamma','brightness','contrast','bloom','shadow','vsync','fps')),
    ('AUDIO', ('audio','sound','music','volume','voice','bgm','sfx','speaker')),
    ('NETWORK', ('network','server','gateway','relay','bishop','goddess','address','host','port','socket','ip','login','account')),
    ('UI', ('ui','interface','dialog','menu','font','chat','hud','toolbar','windowpos','layout')),
    ('INPUT', ('input','mouse','keyboard','key','hotkey','joystick','control')),
    ('RESOURCE', ('resource','path','pak','package','spr','sprite','image','texture','model','map','script','lua','data','file','directory','folder')),
    ('GAMEPLAY', ('gameplay','npc','player','skill','item','quest','mission','team','faction','pk','trade','world','map')),
    ('PERFORMANCE', ('performance','cache','memory','pool','thread','async','lod','quality','detail','optimization')),
    ('DEBUG', ('debug','log','trace','console','developer','test','cheat')),
    ('LOCALIZATION', ('language','locale','charset','font','encoding','region')),
]

def classify_client_subsystem(rel_s, section='', key=''):
    hay=(' %s %s %s ' % (rel_s,section,key)).lower().replace('\\','/')
    scores=[]
    for name,kws in CLIENT_SUBSYSTEM_RULES:
        score=sum(hay.count(k) for k in kws)
        if score:scores.append((score,name))
    if not scores:return 'OTHER'
    scores.sort(key=lambda x:(-x[0],x[1]));return scores[0][1]

def infer_ini_value_type(v):
    s=v.strip().strip('\"').strip("'")
    lo=s.lower()
    if lo in ('true','false','yes','no','on','off','enable','enabled','disable','disabled'):return 'bool'
    if re.match(r'^[-+]?\d+$',s):return 'int'
    if re.match(r'^[-+]?(?:\d+\.\d*|\d*\.\d+)$',s):return 'float'
    if re.match(r'^(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?$',s):return 'ip_or_endpoint'
    if re.search(r'[\\/]|\.[A-Za-z0-9]{1,6}$',s):return 'path_or_file'
    if ',' in s or ';' in s:return 'list_like'
    if not s:return 'empty'
    return 'string'

def parse_ini_text(text):
    rows=[];sections=[];comments=[];section=''
    seen=defaultdict(int)
    for i,line in enumerate(text.splitlines(),1):
        raw=line; s=line.strip()
        if not s:continue
        if s.startswith(';') or s.startswith('#'):
            comments.append((i,s));continue
        m=re.match(r'^\[([^]]+)\]\s*(?:[;#].*)?$',s)
        if m:
            section=m.group(1).strip();sections.append((section,i));continue
        m=re.match(r'^([^=:#][^=:]*?)\s*[=:]\s*(.*)$',raw)
        if not m:continue
        key=m.group(1).strip(); value=m.group(2).strip()
        # Preserve inline comments in raw value; add a cleaned form for navigation.
        clean=value
        q=None;cut=None
        for j,ch in enumerate(value):
            if ch in ('\"',"'"):
                if q==ch:q=None
                elif q is None:q=ch
            elif q is None and ch in (';','#') and (j==0 or value[j-1].isspace()):cut=j;break
        if cut is not None:clean=value[:cut].rstrip()
        identity=(section.lower(),key.lower());seen[identity]+=1
        rows.append({'section':section,'key':key,'value':clean,'raw_value':value,'line':i,'duplicate_ordinal':seen[identity],'value_type':infer_ini_value_type(clean)})
    return sections,rows,comments



# ===== Integrated JX Workshop V4.3 Client Scanner helpers =====
JXW_TEXT_EXTENSIONS = {
    ".ini", ".cfg", ".conf", ".txt", ".tab", ".csv", ".xml", ".json",
    ".lua", ".lst", ".list", ".dat", ".bat", ".cmd", ".log"
}
JXW_HASH_EXTENSIONS = {".spr", ".pak", ".ini", ".cfg", ".txt", ".tab", ".lua", ".exe", ".dll"}
JXW_DEFAULT_EXCLUDED_DIR_NAMES = {".git", ".svn", ".hg", "__pycache__", ".vs", ".idea", ".vscode"}
JXW_NPCRES_HINTS = ("settings/npcres", "spr/npcres", "spr/player", "spr/character")
JXW_RESOURCE_TOKEN_RE = re.compile(r'(?i)(?:[A-Za-z]:)?[\\/][^\r\n\t"\'<>|]+?\.(?:spr|txt|tab|ini|lua|wav|jpg|bmp|pak)\b|[^\s"\'<>|]+?[\\/][^\r\n\t"\'<>|]+?\.(?:spr|txt|tab|ini|lua|wav|jpg|bmp|pak)\b')
JXW_PAK_NAME_RE = re.compile(r'(?i)([^\r\n\t"\']+?\.pak)\b')

JXW_XPACK_HEADER = struct.Struct("<4sIIII12s")      # 32 bytes
JXW_XPACK_INDEX = struct.Struct("<IIII")            # uId,uOffset,lSize,lCompressSizeFlag bits
JXW_TYPE_METHOD_FILTER = 0x0F000000
JXW_TYPE_FILTER = 0xFF000000
JXW_TYPE_FRAME = 0x10000000
JXW_TYPE_NAMES = {0x00000000:"NONE", 0x01000000:"UCL", 0x02000000:"BZIP2", 0x20000000:"UCL_2ND"}


def jxw_display_safe(s):
    if not isinstance(s, str):
        s = str(s)
    return s.encode("utf-8", "backslashreplace").decode("utf-8")


def jxw_write_text_safe(path, text):
    with open(path, "w", encoding="utf-8", errors="backslashreplace", newline="") as f:
        f.write(text)


def jxw_safe_read_text(path: Path, max_bytes=12 * 1024 * 1024):
    try:
        if path.stat().st_size > max_bytes:
            return None, None
    except Exception:
        return None, None
    for enc in ["utf-8-sig", "utf-8", "gbk", "cp936", "big5", "cp1252", "latin-1"]:
        try:
            text = path.read_text(encoding=enc)
            if "\x00" in text[:4096]:
                continue
            return text, enc
        except Exception:
            pass
    return None, None


def jxw_sha1_file(path: Path):
    h = hashlib.sha1()
    try:
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


def jxw_normalize_virtual_path(value: str):
    """Approximate g_GetPackPath + KPakList leading slash behavior for client-root virtual paths."""
    s = value.strip().strip('"\'').replace("/", "\\")
    # remove drive if accidentally captured
    if len(s) >= 2 and s[1] == ":":
        s = s[2:]
    parts = []
    for part in s.split("\\"):
        if part in ("", "."):
            continue
        if part == "..":
            if parts:
                parts.pop()
        else:
            parts.append(part)
    s = "\\".join(parts).lower()
    return "\\" + s if s else "\\"


def jxw_virtual_bytes(path: str):
    """JX is MBCS/VC6. Prefer CP936 bytes; preserve odd legacy names with fallback."""
    p = jxw_normalize_virtual_path(path)
    for enc in ("gbk", "cp936", "latin-1"):
        try:
            return p.encode(enc)
        except Exception:
            pass
    return p.encode("utf-8", "surrogatepass")


def jxw_filename_to_id(path: str):
    """Port of KPakList::FileNameToId, including unsigned 32-bit overflow semantics."""
    data = jxw_virtual_bytes(path)
    uid = 0
    index = 0
    for b in data:
        index += 1
        # MSVC x86 char is signed by default. ASCII uppercase branch occurs before signed conversion matters.
        if 0x41 <= b <= 0x5A:
            c = b + 0x20
        else:
            c = b if b < 0x80 else b - 0x100
        term = (index * c) & 0xFFFFFFFF
        uid = (uid + term) & 0xFFFFFFFF
        uid = (uid % 0x8000000B) & 0xFFFFFFFF
        uid = (uid * 0xFFFFFFEF) & 0xFFFFFFFF
    return (uid ^ 0x12345678) & 0xFFFFFFFF


def jxw_compression_info(flag):
    frame = bool(flag & JXW_TYPE_FRAME)
    method = flag & JXW_TYPE_METHOD_FILTER
    comp_size = flag & (~JXW_TYPE_FILTER & 0xFFFFFFFF)
    return JXW_TYPE_NAMES.get(method, "0x%08X" % method), frame, comp_size


def jxw_parse_xpack(path: Path):
    result = {"valid": False, "error": "", "count": 0, "index_offset": 0, "data_offset": 0,
              "crc32": 0, "entries": [], "size": 0}
    try:
        size = path.stat().st_size
        result["size"] = size
        if size < JXW_XPACK_HEADER.size:
            result["error"] = "too_small"
            return result
        with path.open("rb") as f:
            raw = f.read(JXW_XPACK_HEADER.size)
            if len(raw) != JXW_XPACK_HEADER.size:
                result["error"] = "header_short_read"
                return result
            sig, count, index_off, data_off, crc32, reserved = JXW_XPACK_HEADER.unpack(raw)
            result.update(count=count, index_offset=index_off, data_offset=data_off, crc32=crc32)
            if sig != b"PACK":
                result["error"] = "bad_signature:%r" % (sig,)
                return result
            if count == 0 or index_off < JXW_XPACK_HEADER.size or index_off >= size or data_off < JXW_XPACK_HEADER.size or data_off >= size:
                result["error"] = "invalid_header_ranges"
                return result
            table_size = count * JXW_XPACK_INDEX.size
            if index_off + table_size > size:
                result["error"] = "index_out_of_range"
                return result
            f.seek(index_off)
            raw_index = f.read(table_size)
            if len(raw_index) != table_size:
                result["error"] = "index_short_read"
                return result
            entries = []
            prev_id = None
            bad_offsets = 0
            unsorted = 0
            for i in range(count):
                uid, off, orig_size, flag = JXW_XPACK_INDEX.unpack_from(raw_index, i * JXW_XPACK_INDEX.size)
                method, frame, comp_size = jxw_compression_info(flag)
                # frame-compressed SPR has special internal layout, but offset must still be inside file.
                if off >= size:
                    bad_offsets += 1
                if prev_id is not None and uid < prev_id:
                    unsorted += 1
                prev_id = uid
                entries.append((uid, off, orig_size, flag, method, frame, comp_size))
            if bad_offsets:
                result["error"] = "bad_entry_offsets:%d" % bad_offsets
                return result
            result["entries"] = entries
            result["unsorted_ids"] = unsorted
            result["valid"] = True
            return result
    except Exception as e:
        result["error"] = "%s: %s" % (type(e).__name__, e)
        return result


def jxw_extract_package_ini(client: Path):
    """Read package.ini using the same [Package] Path + numeric keys model as KPakList::Open."""
    candidates = [client / "package.ini", client / "Package.ini", client / "PACKAGE.INI"]
    ini_path = next((p for p in candidates if p.exists()), None)
    if not ini_path:
        return None, "", [], "package.ini not found"
    text, enc = jxw_safe_read_text(ini_path)
    if text is None:
        return ini_path, "", [], "package.ini unreadable"
    section = None
    package_path = ""
    numbered = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith((";", "#")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().lower()
            continue
        if section != "package" or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k, v = k.strip(), v.strip().strip('"\'')
        if k.lower() == "path":
            package_path = v
        elif k.isdigit():
            numbered[int(k)] = v
    ordered = []
    i = 0
    while i in numbered and numbered[i]:
        ordered.append((i, numbered[i]))
        i += 1
    return ini_path, package_path, ordered, "encoding=%s" % enc


def jxw_resolve_pak_path(client: Path, package_path: str, pak_name: str):
    base = Path(package_path.replace("\\", os.sep).replace("/", os.sep)) if package_path else Path("")
    # g_GetFullPath is rooted by engine working path; for scanner try client-relative first.
    if base.is_absolute():
        p = base / pak_name
    else:
        p = client / base / pak_name
    if p.exists():
        return p
    # fallback case-insensitive basename lookup in client tree done by caller if needed
    return p


def jxw_collect_resource_tokens(text):
    out = set()
    for m in JXW_RESOURCE_TOKEN_RE.finditer(text):
        token = m.group(0).strip().strip('"\'').rstrip(",;)")
        if token:
            out.add(jxw_normalize_virtual_path(token))
    return out


def jxw_split_legacy_row(line):
    """Split common JX tabular formats while preserving empty cells where possible."""
    if "\t" in line:
        return line.rstrip("\r\n").split("\t")
    if "," in line and line.count(",") >= 2:
        try:
            return next(csv.reader([line]))
        except Exception:
            pass
    return re.split(r"\s{2,}", line.strip()) if line.strip() else []


def jxw_infer_character_part(source_name, token):
    s=(source_name+" "+token).lower()
    if any(x in s for x in ("_bd", "body", "bodyfile")): return "BODY"
    if any(x in s for x in ("_hd", "head")): return "HEAD"
    if any(x in s for x in ("_rw", "weapon", "weapen")): return "WEAPON"
    if any(x in s for x in ("_cl", "cloth", "clothes", "armor")): return "CLOTHES"
    if any(x in s for x in ("_hh", "_ht", "horse", "mount", "ngua")): return "HORSE/MOUNT"
    if any(x in s for x in ("effect", "_effect", "magic")): return "EFFECT"
    if "shadow" in s: return "SHADOW"
    if "sound" in s or token.lower().endswith(".wav"): return "SOUND"
    return "UNKNOWN"


def jxw_resource_candidate_paths(token, source_rel):
    """Generate conservative virtual-path candidates for an NPCRes table cell."""
    raw=token.strip().strip('"\'').rstrip(',;)')
    if not raw: return []
    ext=Path(raw.replace('\\','/')).suffix.lower()
    out=[]
    def add(v):
        try: nv=jxw_normalize_virtual_path(v)
        except Exception: return
        if nv not in out: out.append(nv)
    if '\\' in raw or '/' in raw:
        add(raw)
    else:
        if ext in ('.txt','.tab','.ini'):
            add('settings/npcres/'+raw)
        elif ext == '.spr':
            # Most player component tables resolve under ResFilePath; these are the useful common roots.
            for root in ('spr/npcres/human/','spr/npcres/style/','spr/npcres/','settings/npcres/'):
                add(root+raw)
        elif ext == '.wav':
            add('sound/'+raw)
    # also source-directory-relative for nested npcres tables
    srcdir=str(Path(source_rel).parent).replace('\\','/')
    if srcdir and srcdir != '.': add(srcdir+'/'+raw)
    return out


def jxw_copy_upload_bundle(output: Path, names, log=None):
    upload=output/'upload'
    try:
        if upload.exists():
            shutil.rmtree(upload)
        upload.mkdir(parents=True, exist_ok=True)
        copied=[]
        for name in names:
            src=output/name
            if src.exists() and src.is_file():
                shutil.copy2(src, upload/name)
                copied.append(name)
        manifest=['JX Client Scanner upload bundle', ''] + copied
        jxw_write_text_safe(upload/'UPLOAD_MANIFEST.txt', '\n'.join(manifest))
        if log: log(f"Upload bundle: {upload} ({len(copied)} files)")
        return copied
    except Exception as e:
        if log: log(f"ERROR creating upload bundle: {e}")
        return []


JXW_SPR_HEADER = struct.Struct("<4sHHHHHHHH6H")
JXW_SPR_OFFS = struct.Struct("<II")
JXW_SPR_PACK_FRAME = struct.Struct("<ii")


def jxw_ucl_nrv2b_decompress_8_py(src: bytes, expected_size: int) -> bytes:
    """Pure Python port of Engine/Src/ucl/n2b_d.c + getbit_8.
    Used so the scanner works even when 64-bit Python cannot load the legacy 32-bit ucl1.dll.
    """
    ilen = 0
    bb = 0
    out = bytearray()
    last_m_off = 1

    def getbit():
        nonlocal bb, ilen
        if bb & 0x7f:
            bb = bb * 2
        else:
            if ilen >= len(src):
                raise ValueError("UCL input overrun while reading bit")
            bb = src[ilen] * 2 + 1
            ilen += 1
        return (bb >> 8) & 1

    while True:
        while getbit():
            if ilen >= len(src):
                raise ValueError("UCL input overrun while copying literal")
            if len(out) >= expected_size:
                raise ValueError("UCL output overrun")
            out.append(src[ilen]); ilen += 1

        m_off = 1
        while True:
            m_off = m_off * 2 + getbit()
            if m_off > 0xFFFFFF + 3:
                raise ValueError("UCL lookbehind offset overflow")
            if getbit():
                break

        if m_off == 2:
            m_off = last_m_off
        else:
            if ilen >= len(src):
                raise ValueError("UCL input overrun while reading offset")
            m_off = (m_off - 3) * 256 + src[ilen]
            ilen += 1
            if m_off == 0xFFFFFFFF:
                break
            m_off += 1
            last_m_off = m_off

        m_len = getbit()
        m_len = m_len * 2 + getbit()
        if m_len == 0:
            m_len = 1
            while True:
                m_len = m_len * 2 + getbit()
                if m_len >= expected_size:
                    raise ValueError("UCL match length overflow")
                if getbit():
                    break
            m_len += 2
        if m_off > 0xD00:
            m_len += 1
        if m_off > len(out):
            raise ValueError("UCL lookbehind overrun")
        copy_count = m_len + 1
        if len(out) + copy_count > expected_size:
            raise ValueError("UCL output overrun during match")
        pos = len(out) - m_off
        for _ in range(copy_count):
            out.append(out[pos]); pos += 1

    if len(out) != expected_size:
        raise ValueError(f"UCL size mismatch: got {len(out)}, expected {expected_size}")
    return bytes(out)


def jxw_native_extract_xpack_entry(pak_path: Path, entry, virtual_path: str, dest_root: Path):
    """Extract one XPack entry according to XPackFile.cpp / KPakMake.cpp.
    Returns (status, output_rel, detail, extracted_size).
    """
    uid, off, orig_size, flag, method, frame, comp_size = entry
    method_bits = flag & JXW_TYPE_METHOD_FILTER
    try:
        with pak_path.open('rb') as f:
            f.seek(off)
            packed = f.read(comp_size)
        if len(packed) != comp_size:
            return 'READ_FAIL', '', f'short read {len(packed)}/{comp_size}', 0

        if not frame:
            if method_bits == 0:
                data = packed
                if len(data) != orig_size:
                    # Legacy update-Pak anomaly probe: never trust it unless UCL produces exact lSize.
                    try:
                        probed = jxw_ucl_nrv2b_decompress_8_py(packed, orig_size)
                        if len(probed) != orig_size:
                            return 'VERIFY_FAIL', '', f'NONE size {len(data)} != {orig_size}', len(data)
                        data = probed
                        method = 'LEGACY_UCL_PROBE'
                    except Exception as probe_e:
                        return 'VERIFY_FAIL', '', f'NONE size {len(data)} != {orig_size}; UCL probe failed: {probe_e}', len(data)
            elif method_bits in (0x01000000, 0x20000000):
                data = jxw_ucl_nrv2b_decompress_8_py(packed, orig_size)
            elif method_bits == 0x02000000:
                return 'UNSUPPORTED_BZIP2', '', 'BZIP2 branch is disabled/commented in source', 0
            else:
                return 'UNSUPPORTED_METHOD', '', f'flag=0x{flag:08X}', 0
        else:
            if method_bits not in (0x01000000, 0x20000000):
                return 'UNSUPPORTED_FRAME_METHOD', '', f'method={method}', 0
            if len(packed) < JXW_SPR_HEADER.size:
                return 'SPR_HEADER_FAIL', '', 'packed SPR shorter than header', 0
            vals = JXW_SPR_HEADER.unpack_from(packed, 0)
            comment = vals[0]; frames = vals[5]; colors = vals[6]
            if comment[:3] != b'SPR':
                return 'SPR_HEADER_FAIL', '', f'bad comment={comment!r}', 0
            prefix_len = JXW_SPR_HEADER.size + colors * 3
            table_len = frames * JXW_SPR_PACK_FRAME.size
            if prefix_len + table_len > len(packed):
                return 'SPR_TABLE_FAIL', '', f'frame table outside packed entry frames={frames}', 0
            prefix = packed[:prefix_len]
            frame_table = [JXW_SPR_PACK_FRAME.unpack_from(packed, prefix_len + i*8) for i in range(frames)]
            cursor = prefix_len + table_len
            frame_blobs=[]; offs=[]; out_off=0
            for i,(csize, usize_signed) in enumerate(frame_table):
                if csize < 0 or cursor + csize > len(packed):
                    return 'SPR_FRAME_READ_FAIL','',f'frame {i} csize={csize}',0
                chunk=packed[cursor:cursor+csize]; cursor += csize
                if usize_signed < 0:
                    expected=-usize_signed
                    if len(chunk) != expected:
                        return 'SPR_FRAME_VERIFY_FAIL','',f'raw frame {i}: {len(chunk)} != {expected}',0
                    blob=chunk
                else:
                    expected=usize_signed
                    blob=jxw_ucl_nrv2b_decompress_8_py(chunk, expected)
                offs.append((out_off,len(blob))); frame_blobs.append(blob); out_off += len(blob)
            data = prefix + b''.join(JXW_SPR_OFFS.pack(a,b) for a,b in offs) + b''.join(frame_blobs)
            if len(data) != orig_size:
                return 'SPR_REBUILD_SIZE_MISMATCH','',f'rebuilt={len(data)} expected={orig_size}',len(data)

        rel = jxw_normalize_virtual_path(virtual_path).lstrip('\\').replace('\\', os.sep)
        dst = dest_root / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(data)
        return 'OK', str(dst.relative_to(dest_root).as_posix()), f'method={method}; frame={int(frame)}', len(data)
    except Exception as e:
        return 'EXTRACT_ERROR', '', f'{type(e).__name__}: {e}', 0

def jxw_native_read_xpack_entry_bytes(pak_path: Path, entry):
    """Read/decompress an XPack entry directly to memory. No output file is created."""
    uid, off, orig_size, flag, method, frame, comp_size = entry
    method_bits = flag & JXW_TYPE_METHOD_FILTER
    with Path(pak_path).open('rb') as f:
        f.seek(off)
        packed = f.read(comp_size)
    if len(packed) != comp_size:
        raise ValueError(f'XPack short read {len(packed)}/{comp_size}')

    if not frame:
        if method_bits == 0:
            if len(packed) == orig_size:
                return packed, f'method=NONE; frame=0'
            # Same verified legacy probe as V4 native extractor.
            data = jxw_ucl_nrv2b_decompress_8_py(packed, orig_size)
            return data, 'method=LEGACY_UCL_PROBE; frame=0'
        if method_bits in (0x01000000, 0x20000000):
            data = jxw_ucl_nrv2b_decompress_8_py(packed, orig_size)
            return data, f'method={method}; frame=0'
        if method_bits == 0x02000000:
            raise ValueError('BZIP2 unsupported in this source branch')
        raise ValueError(f'Unsupported XPack method flag=0x{flag:08X}')

    if method_bits not in (0x01000000, 0x20000000):
        raise ValueError(f'Unsupported SPR frame method={method}')
    if len(packed) < JXW_SPR_HEADER.size:
        raise ValueError('Packed SPR shorter than SPRHEAD')
    vals = JXW_SPR_HEADER.unpack_from(packed, 0)
    comment, frames, colors = vals[0], vals[5], vals[6]
    if not comment.startswith(b'SPR'):
        raise ValueError(f'Packed frame SPR bad signature={comment!r}')
    prefix_len = JXW_SPR_HEADER.size + colors * 3
    table_len = frames * JXW_SPR_PACK_FRAME.size
    if prefix_len + table_len > len(packed):
        raise ValueError('SPR frame table outside packed entry')
    prefix = packed[:prefix_len]
    table = [JXW_SPR_PACK_FRAME.unpack_from(packed, prefix_len+i*8) for i in range(frames)]
    cursor = prefix_len + table_len
    frame_blobs, offs = [], []
    out_off = 0
    for i,(csize,usize_signed) in enumerate(table):
        if csize < 0 or cursor + csize > len(packed):
            raise ValueError(f'SPR frame {i} invalid compressed size={csize}')
        chunk = packed[cursor:cursor+csize]
        cursor += csize
        if usize_signed < 0:
            blob = chunk
            expected = -usize_signed
            if len(blob) != expected:
                raise ValueError(f'SPR raw frame {i} size {len(blob)} != {expected}')
        else:
            blob = jxw_ucl_nrv2b_decompress_8_py(chunk, usize_signed)
        offs.append((out_off, len(blob)))
        frame_blobs.append(blob)
        out_off += len(blob)
    data = prefix + b''.join(JXW_SPR_OFFS.pack(a,b) for a,b in offs) + b''.join(frame_blobs)
    if len(data) != orig_size:
        raise ValueError(f'SPR rebuild {len(data)} != original {orig_size}')
    return data, f'method={method}; frame=1'

def jxw_compose_path_and_name_engine(path_value, name_value):
    """Exact KNpcResNode::ComposePathAndName behavior, normalized for hashing."""
    name=(name_value or '').strip().strip('"\'')
    path=(path_value or '').strip().strip('"\'')
    if not name:
        return ''
    if not path:
        return jxw_normalize_virtual_path(name)
    combined = path
    if not combined.startswith(('\\','/')):
        combined='\\'+combined
    if not combined.endswith(('\\','/')):
        combined+='\\'
    combined += name
    return jxw_normalize_virtual_path(combined)


def jxw_load_legacy_table(path: Path):
    text,enc=jxw_safe_read_text(path)
    if text is None:
        return None,None
    rows=[jxw_split_legacy_row(x) for x in text.splitlines()]
    while rows and not any(c.strip() for c in rows[-1]): rows.pop()
    return rows,enc


def jxw_find_npcres_exact_paths(client: Path, loose_paths, id_locations):
    """Port the SpecialNpc table chain used by KNpcResNode::Init.

    CharacterType table -> PartFileName -> section names -> section resource table
    -> positional action cells -> ComposePathAndName(ResFilePath, spr cell).
    """
    root=None
    for cand in (client/'settings'/'NpcRes', client/'settings'/'npcres'):
        if cand.exists(): root=cand; break
    if root is None:
        # case-insensitive fallback
        settings=client/'settings'
        if settings.exists():
            for d in settings.iterdir():
                if d.is_dir() and d.name.lower()=='npcres': root=d; break
    if root is None: return [],[]

    files=[p for p in root.rglob('*') if p.is_file() and p.suffix.lower() in ('.txt','.tab','.csv')]
    by_base={}
    def filename_aliases(name):
        out=set()
        if not name:
            return out
        s=str(name)
        out.add(s.lower())
        try:
            out.add(s.encode('gbk').decode('latin-1').lower())
        except Exception:
            pass
        try:
            out.add(s.encode('latin-1').decode('gbk').lower())
        except Exception:
            pass
        try:
            out.add(s.encode('cp1252').decode('gbk').lower())
        except Exception:
            pass
        return out

    for p in files:
        for alias in filename_aliases(p.name):
            by_base.setdefault(alias,p)

    table_cache={}
    def get_table(p):
        key=str(p)
        if key not in table_cache: table_cache[key]=jxw_load_legacy_table(p)
        return table_cache[key]
    def resolve_table(name):
        if not name:
            return None
        base=Path(name.replace('\\','/')).name
        for alias in filename_aliases(base):
            p=by_base.get(alias)
            if p is not None:
                return p
        return None

    kind_candidates=[]
    for p in files:
        rows,enc=get_table(p)
        if not rows: continue
        for hi,row in enumerate(rows[:4]):
            heads=[c.strip() for c in row]
            low={c.lower() for c in heads}
            if 'charactertype' in low and 'resfilepath' in low and 'partfilename' in low:
                kind_candidates.append((p,rows,enc,hi)); break

    exact=[]; chains=[]
    for kind_path,rows,enc,hi in kind_candidates:
        headers=[c.strip() for c in rows[hi]]
        hmap={h.lower():i for i,h in enumerate(headers) if h}
        for ri in range(hi+1,len(rows)):
            row=rows[ri]
            def cell_by_header(h):
                idx=hmap.get(h.lower(),-1)
                return row[idx].strip() if 0 <= idx < len(row) else ''
            npc_name=(row[0].strip() if row else '')
            ctype=cell_by_header('CharacterType')
            res_path=cell_by_header('ResFilePath')
            part_name=cell_by_header('PartFileName')
            if not npc_name or not ctype: continue
            chains.append((kind_path.relative_to(client).as_posix(),ri+1,npc_name,ctype,res_path,part_name))
            if ctype.lower()!='specialnpc' or not part_name: continue
            part_path=resolve_table(part_name)
            if not part_path: continue
            part_rows,part_enc=get_table(part_path)
            if not part_rows: continue
            sect_names=[]
            # source: PartFile.GetString(i+2, j+3): row >=2, col >=3 (1-based)
            for pr in part_rows[1:]:
                for val in pr[2:]:
                    v=val.strip()
                    if v and v not in sect_names: sect_names.append(v)
            for part_index,sect in enumerate(sect_names):
                colidx=next((i for i,h in enumerate(headers) if h.strip().lower()==sect.lower()),-1)
                res_table_name=row[colidx].strip() if 0 <= colidx < len(row) else ''
                if not res_table_name: continue
                res_table_path=resolve_table(res_table_name)
                if not res_table_path: continue
                tab_rows,tab_enc=get_table(res_table_path)
                if not tab_rows or len(tab_rows)<2: continue
                action_headers=tab_rows[0]
                for equip_idx,data_row in enumerate(tab_rows[1:]):
                    equip_name=data_row[0].strip() if data_row else str(equip_idx)
                    for action_idx in range(1,len(data_row)):
                        raw=data_row[action_idx].strip()
                        if not raw.lower().endswith('.spr'): continue
                        vp=jxw_compose_path_and_name_engine(res_path,raw)
                        uid=jxw_filename_to_id(vp)
                        locs=sorted(id_locations.get(uid,[]),key=lambda x:x[0])
                        loose=vp in loose_paths
                        first=locs[0] if locs else None
                        state='LOOSE+PAK' if loose and locs else 'LOOSE_ONLY' if loose else 'PAK_ONLY' if locs else 'UNRESOLVED'
                        action_name=action_headers[action_idx].strip() if action_idx < len(action_headers) else str(action_idx-1)
                        exact.append((npc_name,ctype,res_path,part_name,sect,part_index,res_table_name,equip_idx,equip_name,
                                      action_idx-1,action_name,raw,vp,f'0x{uid:08X}',int(loose),len(locs),
                                      ','.join(str(x[0]) for x in locs),';'.join(x[1] for x in locs),
                                      first[0] if first else '',first[1] if first else '',state,
                                      kind_path.relative_to(client).as_posix(),res_table_path.relative_to(client).as_posix()))
    return exact,chains



class WorkshopClientScanner:
    """JX Workshop V4.3 client/resource scanner integrated into Source Intelligence Scanner."""
    def __init__(self, source, output, hash_all, scan_text, native_extract, cancel_event, emit):
        self.source=Path(source); self.output=Path(output)
        self.scan_option_hash_all=bool(hash_all); self.scan_option_scan_text=bool(scan_text); self.scan_option_native_extract=bool(native_extract)
        self.cancel_event=cancel_event; self.emit=emit

    def _scan_check_cancel(self):
        if self.cancel_event.is_set():
            raise RuntimeError('__CANCELLED__')

    def _is_output_dir(self,p):
        try:
            return p.resolve()==self.output.resolve() or is_subpath(p,self.output)
        except Exception:
            return False

    def log(self,msg,progress=None):
        self.emit(('log',str(msg),progress))

    def progress(self,value,phase=None):
        self.emit(('log',('[%s]'%phase) if phase else 'Progress',float(value)))

    def status(self,msg,phase=None):
        self.emit(('log',str(msg),None))

    def scan(self):
        client=self.source; output=self.output
        self.output.mkdir(parents=True, exist_ok=True)
        self._scan_check_cancel()
        errors=[]; ext_counter=Counter(); all_files=[]; loose_paths=set(); known_paths=set(); text_ref_sources=defaultdict(set)
        pak_files=[]; tree=[str(client.resolve())]

        self.log("[1/9] Quét client, tree, manifest và path ứng viên...")
        for current_root,dirs,files in os.walk(client):
            self._scan_check_cancel()
            dirs[:]=sorted(d for d in dirs if d.lower() not in JXW_DEFAULT_EXCLUDED_DIR_NAMES and not self._is_output_dir(Path(current_root)/d))
            current=Path(current_root); rel_dir=current.relative_to(client); indent="    "*len(rel_dir.parts)
            if rel_dir.parts: tree.append(f"{indent}[DIR] {jxw_display_safe(rel_dir.as_posix())}/")
            for fname in sorted(files):
                self._scan_check_cancel()
                p=current/fname
                try: rel=p.relative_to(client); rels=rel.as_posix(); size=p.stat().st_size
                except Exception as e: errors.append(f"{p}: {e}"); continue
                ext=p.suffix.lower(); ext_counter[ext or "[no_ext]"]+=1; tree.append(f"{indent}    {jxw_display_safe(fname)}")
                digest=jxw_sha1_file(p) if (self.scan_option_hash_all or ext in JXW_HASH_EXTENSIONS) else ""
                all_files.append((rels,ext,size,digest))
                vp=jxw_normalize_virtual_path(rels)
                known_paths.add(vp)
                if ext==".spr": loose_paths.add(vp)
                if ext==".pak": pak_files.append(p)
                if self.scan_option_scan_text and ext in JXW_TEXT_EXTENSIONS:
                    text,enc=jxw_safe_read_text(p)
                    if text is not None:
                        for token in jxw_collect_resource_tokens(text):
                            known_paths.add(token); text_ref_sources[token].add(rels)
        jxw_write_text_safe(output/"00_CLIENT_TREE.txt","\n".join(tree))
        with open(output/"01_FILE_MANIFEST.tsv","w",encoding="utf-8",errors="backslashreplace",newline="") as f:
            f.write("relative_path\textension\tsize_bytes\tsha1\n")
            for r in sorted(all_files): f.write("\t".join(map(jxw_display_safe,r))+"\n")
        self.progress(20,'FILE_SCAN')

        self.log("[2/9] Đọc package.ini theo KPakList::Open...")
        ini_path,pkg_path,pkg_order,pkg_note=jxw_extract_package_ini(client)
        order_by_name={name.lower():idx for idx,name in pkg_order}
        # basename lookup for config paths that don't resolve exactly
        by_basename=defaultdict(list)
        for p in pak_files: by_basename[p.name.lower()].append(p)
        ordered_paks=[]; used=set()
        for idx,name in pkg_order:
            expected=jxw_resolve_pak_path(client,pkg_path,name)
            actual=expected if expected.exists() else (by_basename.get(Path(name).name.lower(),[None])[0])
            if actual and actual.exists():
                ordered_paks.append((idx,name,actual)); used.add(str(actual.resolve()).lower())
            else:
                ordered_paks.append((idx,name,None))
        extra_index=(max([x[0] for x in ordered_paks],default=-1)+1)
        for p in sorted(pak_files):
            if str(p.resolve()).lower() not in used:
                ordered_paks.append((extra_index,p.name,p)); extra_index+=1
        self.log(f"  package.ini: {ini_path if ini_path else 'NOT FOUND'}; configured={len(pkg_order)}; discovered={len(pak_files)}")
        self.progress(28,'PACKAGE_INI')

        self.log("[3/9] Parse header + index của từng XPack...")
        parsed={}; pak_summary=[]; id_locations=defaultdict(list)
        for pos,(order_idx,config_name,p) in enumerate(ordered_paks):
            if p is None:
                pak_summary.append((order_idx,config_name,"",0,"MISSING",0,0,0,0,"configured pak not found")); continue
            xp=jxw_parse_xpack(p); parsed[p]=xp
            relp=jxw_display_safe(p.relative_to(client).as_posix()) if str(p).lower().startswith(str(client).lower()) else jxw_display_safe(str(p))
            status="VALID" if xp["valid"] else "INVALID/UNSUPPORTED"
            pak_summary.append((order_idx,config_name,relp,xp["size"],status,xp["count"],xp["index_offset"],xp["data_offset"],xp["crc32"],xp.get("error","") or ("unsorted_ids=%d"%xp.get("unsorted_ids",0))))
            if xp["valid"]:
                for elem_idx,e in enumerate(xp["entries"]):
                    id_locations[e[0]].append((order_idx,config_name,p,elem_idx,e))
            if pos % 3 == 0:
                self.progress(28+22*(pos+1)/max(len(ordered_paks),1),'XPACK_PARSE'); self._scan_check_cancel()
        with open(output/"08_XPACK_SUMMARY.tsv","w",encoding="utf-8",errors="backslashreplace",newline="") as f:
            f.write("pak_order\tconfig_name\tactual_path\tfile_size\tstatus\tentry_count\tindex_offset\tdata_offset\tcrc32\tnote\n")
            for r in pak_summary: f.write("\t".join(jxw_display_safe(x) for x in r)+"\n")

        self.log("[4/9] Xuất raw XPack index...")
        with open(output/"09_XPACK_INDEX.tsv","w",encoding="utf-8",errors="backslashreplace",newline="") as f:
            f.write("pak_order\tpak_name\telem_index\tuId_hex\tuId_dec\toffset\toriginal_size\tcompress_flag_hex\tmethod\tframe_compressed\tcompressed_size_field\n")
            for order_idx,config_name,p in ordered_paks:
                if not p or not parsed.get(p,{}).get("valid"): continue
                for i,e in enumerate(parsed[p]["entries"]):
                    uid,off,orig,flag,method,frame,comp=e
                    f.write(f"{order_idx}\t{jxw_display_safe(config_name)}\t{i}\t0x{uid:08X}\t{uid}\t{off}\t{orig}\t0x{flag:08X}\t{method}\t{int(frame)}\t{comp}\n")
        self.progress(55,'XPACK_PARSE')

        self.log("[5/9] Tính JX FileNameToId cho path ứng viên và dò qua Pak...")
        path_matches=[]
        for vp in sorted(known_paths):
            uid=jxw_filename_to_id(vp); locs=sorted(id_locations.get(uid,[]),key=lambda x:x[0])
            sources=";".join(sorted(text_ref_sources.get(vp,set())))
            if locs:
                for rank,loc in enumerate(locs):
                    order_idx,pak_name,p,elem_idx,e=loc
                    path_matches.append((vp,uid,order_idx,pak_name,elem_idx,e[1],e[2],e[3],e[4],int(e[5]),e[6],rank==0,sources))
            else:
                path_matches.append((vp,uid,"","","","","","","","","",False,sources))
        with open(output/"10_KNOWN_PATH_TO_PAK.tsv","w",encoding="utf-8",errors="backslashreplace",newline="") as f:
            f.write("virtual_path\tuId_hex\tpak_order\tpak_name\telem_index\toffset\toriginal_size\tcompress_flag_hex\tmethod\tframe\tcompressed_size_field\tfirst_pak_winner\treference_sources\n")
            for r in path_matches:
                vp,uid,*rest=r
                vals=[vp,f"0x{uid:08X}"]+list(rest)
                if len(vals)>7 and isinstance(vals[7],int): vals[7]=f"0x{vals[7]:08X}"
                f.write("\t".join(jxw_display_safe(x) for x in vals)+"\n")
        self.progress(70,'PATH_MATCH')

        self.log("[6/9] Phân tích override loose ↔ Pak và trace nhân vật...")
        override_rows=[]; character_rows=[]
        for vp in sorted(known_paths):
            uid=jxw_filename_to_id(vp); locs=sorted(id_locations.get(uid,[]),key=lambda x:x[0]); is_loose=vp in loose_paths
            first=locs[0] if locs else None
            pak_orders=",".join(str(x[0]) for x in locs); pak_names=";".join(x[1] for x in locs)
            if is_loose and locs:
                override_rows.append((vp,f"0x{uid:08X}",1,len(locs),pak_orders,pak_names,first[0],first[1],"Depends on g_SetPakFileMode: disk-first => loose wins; pak-first => first Pak wins"))
            low=vp.lower().replace("\\","/")
            if any(h in low for h in JXW_NPCRES_HINTS):
                character_rows.append((vp,f"0x{uid:08X}",int(is_loose),len(locs),pak_orders,pak_names,(first[0] if first else ""),(first[1] if first else ""),";".join(sorted(text_ref_sources.get(vp,set())))))
        with open(output/"11_OVERRIDE_ANALYSIS.tsv","w",encoding="utf-8",errors="backslashreplace",newline="") as f:
            f.write("virtual_path\tuId_hex\tloose_exists\tpak_copy_count\tpak_orders\tpak_names\tfirst_pak_order\tfirst_pak_name\tprecedence_note\n")
            for r in override_rows: f.write("\t".join(jxw_display_safe(x) for x in r)+"\n")
        with open(output/"12_CHARACTER_PAK_TRACE.tsv","w",encoding="utf-8",errors="backslashreplace",newline="") as f:
            f.write("virtual_path\tuId_hex\tloose_exists\tpak_copy_count\tpak_orders\tpak_names\tfirst_pak_order\tfirst_pak_name\treference_sources\n")
            for r in character_rows: f.write("\t".join(jxw_display_safe(x) for x in r)+"\n")

        with open(output/"13_DUPLICATE_PAK_IDS.tsv","w",encoding="utf-8",errors="backslashreplace",newline="") as f:
            f.write("uId_hex\tcopy_count\tpak_orders\tpak_names\telem_indexes\n")
            for uid,locs in sorted(id_locations.items()):
                if len(locs)>1:
                    locs=sorted(locs,key=lambda x:x[0])
                    f.write(f"0x{uid:08X}\t{len(locs)}\t{','.join(str(x[0]) for x in locs)}\t{';'.join(jxw_display_safe(x[1]) for x in locs)}\t{','.join(str(x[3]) for x in locs)}\n")
        self.progress(88,'NPCRES_PARSE')

        self.log("[7/9] Parse settings/npcres thành bảng cell + resource references...")
        npcres_cells=[]; npcres_refs=[]
        npcres_files=[]
        for rels,ext,size,digest in all_files:
            low=rels.lower().replace('\\','/')
            if 'settings/npcres/' in low and ext in JXW_TEXT_EXTENSIONS:
                npcres_files.append((rels,ext,size))
                fp=client / Path(rels.replace('/', os.sep))
                text,enc=jxw_safe_read_text(fp)
                if text is None:
                    continue
                for row_no,line in enumerate(text.splitlines(),1):
                    cells=jxw_split_legacy_row(line)
                    for col_no,cell in enumerate(cells,1):
                        val=cell.strip()
                        if not val: continue
                        npcres_cells.append((rels,enc or '',row_no,col_no,val))
                        # find every explicit resource extension in a cell, including bare filenames
                        for m in re.finditer(r'(?i)([^\t\r\n"\'<>|,;]+?\.(?:spr|txt|tab|ini|wav))\b', val):
                            tok=m.group(1).strip()
                            cands=jxw_resource_candidate_paths(tok, rels)
                            npcres_refs.append((rels,enc or '',row_no,col_no,val,tok,jxw_infer_character_part(rels,tok),';'.join(cands)))
        with open(output/'15_NPCRES_TABLE_CELLS.tsv','w',encoding='utf-8',errors='backslashreplace',newline='') as f:
            f.write('source_file\tencoding\trow\tcolumn\tcell_value\n')
            for r in npcres_cells: f.write('\t'.join(jxw_display_safe(x) for x in r)+'\n')
        with open(output/'16_CHARACTER_RESOURCE_REFERENCES.tsv','w',encoding='utf-8',errors='backslashreplace',newline='') as f:
            f.write('source_file\tencoding\trow\tcolumn\tcell_value\traw_resource\tinferred_part\tcandidate_virtual_paths\n')
            for r in npcres_refs: f.write('\t'.join(jxw_display_safe(x) for x in r)+'\n')
        self.progress(91,'CHARACTER_RESOLVE')

        self.log("[8/9] Resolve từng resource NPC/player sang loose/Pak/order...")
        resolver_rows=[]; player_rows=[]
        for src,enc,row_no,col_no,cell,tok,part,cands_joined in npcres_refs:
            cands=[x for x in cands_joined.split(';') if x]
            resolved_any=False
            for vp in cands:
                uid=jxw_filename_to_id(vp)
                locs=sorted(id_locations.get(uid,[]),key=lambda x:x[0])
                is_loose=vp in loose_paths
                if not is_loose and not locs:
                    continue
                resolved_any=True
                first=locs[0] if locs else None
                state=('LOOSE+PAK' if is_loose and locs else 'LOOSE_ONLY' if is_loose else 'PAK_ONLY')
                row=(src,row_no,col_no,tok,part,vp,f'0x{uid:08X}',int(is_loose),len(locs),
                     ','.join(str(x[0]) for x in locs),';'.join(x[1] for x in locs),
                     first[0] if first else '',first[1] if first else '',state)
                resolver_rows.append(row)
                low=(src+' '+vp).lower().replace('\\','/')
                if ('spr/npcres/human/' in low or any(k in low for k in ('dnn','dsn','gsn','jsf','jsm','jsx','player','partfilename'))):
                    player_rows.append(row)
            if not resolved_any:
                vp=cands[0] if cands else ''
                uid=jxw_filename_to_id(vp) if vp else 0
                row=(src,row_no,col_no,tok,part,vp,(f'0x{uid:08X}' if vp else ''),0,0,'','','','','UNRESOLVED')
                resolver_rows.append(row)
                low=(src+' '+tok).lower()
                if any(k in low for k in ('dnn','dsn','gsn','jsf','jsm','jsx','player','partfilename')):
                    player_rows.append(row)
        header='source_file\trow\tcolumn\traw_resource\tinferred_part\tresolved_virtual_path\tuId_hex\tloose_exists\tpak_copy_count\tpak_orders\tpak_names\tfirst_pak_order\tfirst_pak_name\tstate\n'
        with open(output/'17_CHARACTER_RESOLVER.tsv','w',encoding='utf-8',errors='backslashreplace',newline='') as f:
            f.write(header)
            for r in resolver_rows: f.write('\t'.join(jxw_display_safe(x) for x in r)+'\n')
        with open(output/'18_PLAYER_RESOURCE_CANDIDATES.tsv','w',encoding='utf-8',errors='backslashreplace',newline='') as f:
            f.write(header)
            seen=set()
            for r in player_rows:
                key=tuple(r)
                if key in seen: continue
                seen.add(key); f.write('\t'.join(jxw_display_safe(x) for x in r)+'\n')
        self.log('[9/13] Exact KNpcRes path resolver theo CharacterType/PartFileName/ResFilePath...')
        exact_rows,character_chains=jxw_find_npcres_exact_paths(client,loose_paths,id_locations)
        exact_header=('npc_name\tcharacter_type\tres_file_path\tpart_file_name\tsection_name\tpart_index\tresource_table\tequip_index\tequip_name\t'
                      'action_index\taction_name\traw_spr\texact_virtual_path\tuId_hex\tloose_exists\tpak_copy_count\tpak_orders\tpak_names\tfirst_pak_order\tfirst_pak_name\tstate\tkind_table\tresource_table_path\n')
        with open(output/'24_EXACT_CHARACTER_PATHS.tsv','w',encoding='utf-8',errors='backslashreplace',newline='') as f:
            f.write(exact_header)
            for r in exact_rows:f.write('\t'.join(jxw_display_safe(x) for x in r)+'\n')
        with open(output/'25_CHARACTER_CHAIN_SUMMARY.tsv','w',encoding='utf-8',errors='backslashreplace',newline='') as f:
            f.write('kind_table\trow\tnpc_name\tcharacter_type\tres_file_path\tpart_file_name\n')
            for r in character_chains:f.write('\t'.join(jxw_display_safe(x) for x in r)+'\n')
        exact_states=Counter(r[20] for r in exact_rows)
        # V4.3 reverse graph: exact SPR -> every KNpcRes caller.
        with open(output/'27_RESOURCE_REFERENCE_GRAPH.tsv','w',encoding='utf-8',errors='backslashreplace',newline='') as f:
            f.write('virtual_path\tuId_hex\tnpc_name\tcharacter_type\tsection_name\tresource_table\tresource_table_path\tequip_index\tequip_name\taction_index\taction_name\traw_spr\tstate\n')
            for x in exact_rows:
                vals=(x[12],x[13],x[0],x[1],x[4],x[6],x[22],x[7],x[8],x[9],x[10],x[11],x[20])
                f.write('\t'.join(jxw_display_safe(v) for v in vals)+'\n')
        self.log(f"  Exact SPR rows: {len(exact_rows)}; resolved={len(exact_rows)-exact_states.get('UNRESOLVED',0)}; unresolved={exact_states.get('UNRESOLVED',0)}")
        self.progress(96,'NATIVE_EXTRACT')

        self.log('[10/13] Native PAK audit + lập targeted extraction plan...')
        compression_counts=Counter()
        for order_idx,config_name,pakp in ordered_paks:
            if not pakp or not parsed.get(pakp,{}).get('valid'): continue
            for e in parsed[pakp]['entries']:
                compression_counts[(e[4],int(e[5]))]+=1
        with open(output/'20_XPACK_COMPRESSION_AUDIT.tsv','w',encoding='utf-8',errors='backslashreplace',newline='') as f:
            f.write('method\tframe_compressed\tentry_count\n')
            for (method,frame),cnt in sorted(compression_counts.items()):
                f.write(f'{method}\t{frame}\t{cnt}\n')

        # Unique first-winner PAK targets from resolved player rows + known character paths.
        plan_by_path={}
        resolver_iter=list(player_rows)
        for r in resolver_iter:
            vp=r[5]; state=r[-1]
            if not vp or state not in ('PAK_ONLY','LOOSE+PAK'): continue
            uid=jxw_filename_to_id(vp); locs=sorted(id_locations.get(uid,[]),key=lambda x:x[0])
            if not locs: continue
            loc=locs[0]
            plan_by_path.setdefault(vp,(r[4],state,uid,loc))
        for r in character_rows:
            vp=r[0]; uid=jxw_filename_to_id(vp); locs=sorted(id_locations.get(uid,[]),key=lambda x:x[0])
            if locs and vp not in plan_by_path:
                plan_by_path[vp]=('CHARACTER/NPCRES','PAK_MATCH',uid,locs[0])
        # V4.1 exact engine paths have priority and greatly expand targeted player resources.
        for r in exact_rows:
            vp=r[12]; state=r[20]
            if state not in ('PAK_ONLY','LOOSE+PAK') or not vp: continue
            uid=jxw_filename_to_id(vp); locs=sorted(id_locations.get(uid,[]),key=lambda x:x[0])
            if locs: plan_by_path[vp]=(r[4], 'EXACT_'+state, uid, locs[0])

        extract_plan=[]
        for vp,(part,state,uid,loc) in sorted(plan_by_path.items()):
            order_idx,pak_name,pakp,elem_idx,e=loc
            extract_plan.append((vp,f'0x{uid:08X}',part,state,order_idx,pak_name,elem_idx,e[1],e[2],f'0x{e[3]:08X}',e[4],int(e[5]),e[6],str(pakp)))
        with open(output/'21_NATIVE_EXTRACT_PLAN.tsv','w',encoding='utf-8',errors='backslashreplace',newline='') as f:
            f.write('virtual_path\tuId_hex\tinferred_part\tresolver_state\tpak_order\tpak_name\telem_index\toffset\toriginal_size\tcompress_flag_hex\tmethod\tframe\tcompressed_size\tpak_path\n')
            for r in extract_plan: f.write('\t'.join(jxw_display_safe(x) for x in r)+'\n')

        self.log(f"  Target PAK resources: {len(extract_plan)}")
        self.log("[11/13] Native targeted extraction theo XPackFile.cpp...")
        extract_results=[]; extract_root=output/'extracted_character'
        if self.scan_option_native_extract:
            if extract_root.exists(): shutil.rmtree(extract_root)
            extract_root.mkdir(parents=True,exist_ok=True)
            for i,r in enumerate(extract_plan):
                vp=r[0]; uid=jxw_filename_to_id(vp); loc=sorted(id_locations.get(uid,[]),key=lambda x:x[0])[0]
                order_idx,pak_name,pakp,elem_idx,e=loc
                status,outrel,detail,esize=jxw_native_extract_xpack_entry(pakp,e,vp,extract_root)
                extract_results.append((vp,f'0x{uid:08X}',order_idx,pak_name,elem_idx,e[4],int(e[5]),e[2],e[6],status,esize,outrel,detail))
                if i and i%100==0:
                    self.log(f"  extracted {i}/{len(extract_plan)}...")
                    self._scan_check_cancel()
        else:
            for r in extract_plan:
                extract_results.append((r[0],r[1],r[4],r[5],r[6],r[10],r[11],r[8],r[12],'SKIPPED',0,'','Native extraction disabled by user'))
        with open(output/'22_NATIVE_EXTRACT_RESULTS.tsv','w',encoding='utf-8',errors='backslashreplace',newline='') as f:
            f.write('virtual_path\tuId_hex\tpak_order\tpak_name\telem_index\tmethod\tframe\toriginal_size\tcompressed_size\tstatus\textracted_size\toutput_relative\tdetail\n')
            for r in extract_results: f.write('\t'.join(jxw_display_safe(x) for x in r)+'\n')

        self.log("[12/13] Tạo report V4/V4.1, stats và folder upload...")
        valid_paks=sum(1 for x in parsed.values() if x.get("valid")); invalid_paks=sum(1 for x in parsed.values() if not x.get("valid"))
        matched_paths=sum(1 for vp in known_paths if id_locations.get(jxw_filename_to_id(vp)))
        duplicate_ids=sum(1 for locs in id_locations.values() if len(locs)>1)
        stats={
            "app":APP_TITLE,"version":VERSION,"scan_time":datetime.now().isoformat(timespec="seconds"),
            "client_root":str(client.resolve()),"output_root":str(output.resolve()),"total_files":len(all_files),
            "pak_files_discovered":len(pak_files),"pak_entries_from_package_ini":len(pkg_order),"valid_xpack_files":valid_paks,
            "invalid_or_unsupported_paks":invalid_paks,"total_xpack_index_entries":sum(len(x.get("entries",[])) for x in parsed.values()),
            "known_virtual_paths":len(known_paths),"known_paths_found_in_paks":matched_paths,"loose_spr_files":len(loose_paths),
            "loose_paths_also_in_pak":len(override_rows),"character_trace_rows":len(character_rows),"duplicate_ids_across_paks":duplicate_ids,
            "npcres_text_files_parsed":len(npcres_files),"npcres_table_cells":len(npcres_cells),"npcres_resource_references":len(npcres_refs),"character_resolver_rows":len(resolver_rows),"player_resource_candidate_rows":len(player_rows),
            "exact_character_rows":len(exact_rows),"exact_character_resolved":sum(1 for x in exact_rows if x[20] != 'UNRESOLVED'),"exact_character_unresolved":sum(1 for x in exact_rows if x[20] == 'UNRESOLVED'),
            "native_extract_targets":len(extract_plan),"native_extract_ok":sum(1 for x in extract_results if x[9]=='OK'),"native_extract_failed_or_unsupported":sum(1 for x in extract_results if x[9] not in ('OK','SKIPPED')),
            "extensions":dict(sorted(ext_counter.items(),key=lambda x:(-x[1],x[0]))),"errors":len(errors)
        }
        jxw_write_text_safe(output/"07_STATS.json",json.dumps(stats,ensure_ascii=False,indent=2))
        if errors: jxw_write_text_safe(output/"99_ERRORS.txt","\n".join(jxw_display_safe(x) for x in errors))
        report=f"""# JX CLIENT SCANNER V2 REPORT\n\nGenerated: {datetime.now().isoformat(timespec='seconds')}\n\nClient: `{jxw_display_safe(client.resolve())}`\n\n## Pak/XPack\n\n- package.ini: `{jxw_display_safe(ini_path) if ini_path else 'NOT FOUND'}`\n- Package Path: `{jxw_display_safe(pkg_path)}`\n- Configured Pak entries: **{len(pkg_order)}**\n- Pak files discovered: **{len(pak_files)}**\n- Valid XPack: **{valid_paks}**\n- Invalid/unsupported: **{invalid_paks}**\n- Total XPack index entries: **{stats['total_xpack_index_entries']}**\n\n## Path matching\n\n- Known virtual paths: **{len(known_paths)}**\n- Known paths found by exact JX FileNameToId in Pak: **{matched_paths}**\n- Loose SPR: **{len(loose_paths)}**\n- Loose paths also present in at least one Pak: **{len(override_rows)}**\n- Character/NpcRes trace rows: **{len(character_rows)}**\n- IDs duplicated across multiple Pak: **{duplicate_ids}**\n\n## Important interpretation\n\nXPack stores IDs, not original filenames. `10_KNOWN_PATH_TO_PAK.tsv` reconstructs membership by applying the same `KPakList::FileNameToId` algorithm to known client/config/resource paths and matching the resulting ID against XPack index entries.\n\nAmong Pak files, lower package order wins because KPakList scans packages from first to last. Disk-vs-Pak precedence still depends on runtime `g_SetPakFileMode`; therefore `11_OVERRIDE_ANALYSIS.tsv` reports both sides instead of assuming one.\n\n## Upload back to ChatGPT\n\nPrioritize: `08_XPACK_SUMMARY.tsv`, `10_KNOWN_PATH_TO_PAK.tsv`, `11_OVERRIDE_ANALYSIS.tsv`, `12_CHARACTER_PAK_TRACE.tsv`, `13_DUPLICATE_PAK_IDS.tsv`, `14_V2_REPORT.md`, `07_STATS.json`.\n"""
        jxw_write_text_safe(output/"14_V2_REPORT.md",report)
        state_counts=Counter(r[-1] for r in resolver_rows)
        v3_report=f"""# JX CLIENT SCANNER V3 — CHARACTER RESOURCE RESOLVER

        Generated: {datetime.now().isoformat(timespec='seconds')}

        Client: `{jxw_display_safe(client.resolve())}`

        ## NPCRes parsing

        - NPCRes text files parsed: **{len(npcres_files)}**
        - Non-empty table cells captured: **{len(npcres_cells)}**
        - Resource references discovered in NPCRes cells: **{len(npcres_refs)}**
        - Resolver rows: **{len(resolver_rows)}**
        - Player/human candidate rows: **{len(player_rows)}**

        ## Resolver states

        - LOOSE_ONLY: **{state_counts.get('LOOSE_ONLY',0)}**
        - PAK_ONLY: **{state_counts.get('PAK_ONLY',0)}**
        - LOOSE+PAK: **{state_counts.get('LOOSE+PAK',0)}**
        - UNRESOLVED: **{state_counts.get('UNRESOLVED',0)}**

        ## Files to inspect first

        - `16_CHARACTER_RESOURCE_REFERENCES.tsv` — exact source table/row/column and raw resource text.
        - `17_CHARACTER_RESOLVER.tsv` — resolved path with loose/Pak/order state.
        - `18_PLAYER_RESOURCE_CANDIDATES.tsv` — player/human-focused shortlist.
        - `12_CHARACTER_PAK_TRACE.tsv` — compatibility trace from V2.

        ## Upload bundle

        Scanner creates `upload\\` automatically after all reports are finished. The root mapping directory still retains every full output file.
        """
        jxw_write_text_safe(output/'19_V3_REPORT.md',v3_report)
        result_counts=Counter(r[9] for r in extract_results)
        v4_report=f"""# JX CLIENT SCANNER V4 — NATIVE PAK READER & CHARACTER EXTRACTOR

        Generated: {datetime.now().isoformat(timespec='seconds')}

        Client: `{jxw_display_safe(client.resolve())}`

        ## Source-grounded XPack behavior

        - Native methods implemented: NONE, UCL, UCL_2ND.
        - FRAME SPR: rebuilds original SPR from SPRHEAD + palette + per-frame table/data.
        - BZIP2 is detected but intentionally marked unsupported because the BZIP2 calls are commented out in the source branch used as reference.

        ## Compression audit

        """
        for (method,frame),cnt in sorted(compression_counts.items()):
            v4_report += f"- {method}, frame={frame}: **{cnt}** entries\n"
        v4_report += f"""

        ## Targeted extraction

        - Planned character/NpcRes PAK resources: **{len(extract_plan)}**
        - Native extraction enabled: **{self.scan_option_native_extract}**
        - OK: **{result_counts.get('OK',0)}**
        - Failed/unsupported: **{sum(v for k,v in result_counts.items() if k not in ('OK','SKIPPED'))}**
        - Extracted binaries folder: `extracted_character\\` (not copied into upload bundle)

        ## Outputs

        - `20_XPACK_COMPRESSION_AUDIT.tsv`
        - `21_NATIVE_EXTRACT_PLAN.tsv`
        - `22_NATIVE_EXTRACT_RESULTS.tsv`
        - `23_V4_REPORT.md`

        The upload bundle contains reports/manifests only; extracted binary resources remain in the root mapping folder to avoid creating an oversized upload bundle.
        """
        jxw_write_text_safe(output/'23_V4_REPORT.md',v4_report)
        legacy_probe_ok=sum(1 for x in extract_results if 'LEGACY_UCL_PROBE' in x[12])
        v41_report=f"""# JX CLIENT SCANNER V4.2 — SMOOTH SPR ANIMATION + PNG EXPORT

        Generated: {datetime.now().isoformat(timespec='seconds')}

        ## Exact KNpcRes chain

        The resolver follows the source chain: CharacterType -> ResFilePath + PartFileName -> part section names -> resource table -> positional action cell -> ComposePathAndName().

        - Character rows resolved from exact tables: **{len(exact_rows)}**
        - Resolved to loose and/or Pak: **{sum(1 for x in exact_rows if x[20] != 'UNRESOLVED')}**
        - Still unresolved: **{sum(1 for x in exact_rows if x[20] == 'UNRESOLVED')}**
        - LOOSE_ONLY: **{exact_states.get('LOOSE_ONLY',0)}**
        - PAK_ONLY: **{exact_states.get('PAK_ONLY',0)}**
        - LOOSE+PAK: **{exact_states.get('LOOSE+PAK',0)}**

        ## Native extraction

        - Targets after exact resolver: **{len(extract_plan)}**
        - OK: **{sum(1 for x in extract_results if x[9]=='OK')}**
        - Legacy NONE entries successfully verified as UCL probe: **{legacy_probe_ok}**

        ## SPR Viewer

        The second application tab reads standard loose/rebuilt SPR files directly: SPRHEAD, RGB palette, SPROFFS, SPRFRAME and JX RLE blocks. It supports frame navigation, playback and 1x-4x zoom.

        ## New V4.1 outputs

        - `24_EXACT_CHARACTER_PATHS.tsv`
        - `25_CHARACTER_CHAIN_SUMMARY.tsv`
        - `26_V4_1_REPORT.md`
        """
        jxw_write_text_safe(output/'26_V4_1_REPORT.md',v41_report)
        v43_report=f"""# JX CLIENT SCANNER V4.3 — RESOURCE STUDIO

        Generated: {datetime.now().isoformat(timespec='seconds')}

        ## New V4.3 capabilities

        - Direct SPR viewing from XPack/PAK: selected entry is decompressed in memory, then passed to SPR Viewer.
        - Extract SPR + sidecar TXT with virtual path, hash, Pak/order/entry and NpcRes references.
        - Reverse reference graph: `27_RESOURCE_REFERENCE_GRAPH.tsv`.
        - Replace Same Path: copies a validated SPR to the exact loose virtual path without changing NpcRes.
        - Replace + Relink: backs up affected NpcRes tables, replaces only indexed exact SPR tokens, copies the new SPR beside the old virtual path, and writes `REPLACE_LAST_REPORT.txt`.
        - Resource Studio remains conservative: XPack stores hashes only, so browsable paths are paths reconstructed from scanner/mapping knowledge.
        """
        jxw_write_text_safe(output/'28_V4_3_REPORT.md',v43_report)
        upload_names=[
            '07_STATS.json','08_XPACK_SUMMARY.tsv','10_KNOWN_PATH_TO_PAK.tsv','11_OVERRIDE_ANALYSIS.tsv',
            '12_CHARACTER_PAK_TRACE.tsv','13_DUPLICATE_PAK_IDS.tsv','14_V2_REPORT.md',
            '15_NPCRES_TABLE_CELLS.tsv','16_CHARACTER_RESOURCE_REFERENCES.tsv','17_CHARACTER_RESOLVER.tsv',
            '18_PLAYER_RESOURCE_CANDIDATES.tsv','19_V3_REPORT.md',
            '20_XPACK_COMPRESSION_AUDIT.tsv','21_NATIVE_EXTRACT_PLAN.tsv','22_NATIVE_EXTRACT_RESULTS.tsv','23_V4_REPORT.md',
            '24_EXACT_CHARACTER_PATHS.tsv','25_CHARACTER_CHAIN_SUMMARY.tsv','26_V4_1_REPORT.md',
            '27_RESOURCE_REFERENCE_GRAPH.tsv','28_V4_3_REPORT.md'
        ]
        copied=jxw_copy_upload_bundle(output,upload_names,self.log)
        self.progress(100,"DONE"); self.status("Hoàn tất V4.3.","DONE")
        self.log(""); self.log("HOÀN TẤT V4.3."); self.log(f"Valid XPack: {valid_paks}; resolver rows: {len(resolver_rows)}; player candidates: {len(player_rows)}")
        self.log(f"Kết quả: {output}"); self.log(f"Upload: {output/'upload'}")
        return stats

class ClientIniScanner:
    def __init__(self,source,output,max_bytes,incremental,clean_generated,cancel_event,emit):
        self.source=source;self.output=output;self.max_bytes=max_bytes;self.incremental=incremental;self.clean_generated=clean_generated;self.cancel_event=cancel_event;self.emit=emit;self.warnings=[]
        self.cache_path=output/'.jxsi_client_ini_cache.json';self.old_cache={};self.new_cache={}
    def cancelled(self):
        if self.cancel_event.is_set():raise RuntimeError('__CANCELLED__')
    def log(self,msg,progress=None):self.emit(('log',msg,progress))
    def warn(self,rel,stage,err,action='continued'):self.warnings.append((rel,stage,err,action))
    def clean_output(self):
        if not self.clean_generated:return
        for name in ('INI_MODULES','AI_PACKS','CHATGPT_UPLOADED'):
            p=self.output/name
            if p.exists():
                try:shutil.rmtree(str(p))
                except Exception as e:self.warn(name,'clean_output',repr(e),'left old directory')
        for p in self.output.glob('*'):
            if p.is_file() and (p.name.startswith(('00_','01_','02_','03_','04_','05_','06_','07_','08_','09_','10_','11_','12_','13_','14_','15_','16_','17_','18_','98_','99_','AI_'))):
                try:p.unlink()
                except Exception as e:self.warn(p.name,'clean_output',repr(e),'left old file')
    def load_cache(self):
        if self.incremental and self.cache_path.exists():
            try:self.old_cache=json.loads(self.cache_path.read_text(encoding='utf-8'))
            except Exception as e:self.warn(self.cache_path.name,'load_cache',repr(e),'ignored cache')
    def scan(self):
        started=time.time();self.output.mkdir(parents=True,exist_ok=True);self.load_cache();self.clean_output()
        self.log('CLIENT INI SOURCE : %s'%self.source.resolve());self.log('CLIENT INI OUTPUT : %s'%self.output.resolve())
        if is_subpath(self.output,self.source):self.log('Safety: Output nằm trong Client Source -> tự động loại Output khỏi scan.')
        tree=[str(self.source.resolve())];recs=[];ignored=[];hits=0;misses=0;out_resolved=self.output.resolve()
        self.log('1/8 Quét .ini client',5)
        for cr,dirs,files in os.walk(str(self.source)):
            self.cancelled();cur=Path(cr);rel_dir=cur.relative_to(self.source);filtered=[]
            for d in dirs:
                dp=cur/d
                if d.lower() in BUILD_DIR_NAMES:continue
                try:
                    if is_subpath(dp,out_resolved) or dp.resolve()==out_resolved:continue
                except Exception:pass
                filtered.append(d)
            dirs[:]=filtered;indent='    '*len(rel_dir.parts)
            if rel_dir.parts:tree.append('%s[DIR] %s/'%(indent,rel_dir.as_posix()))
            for fn in sorted(files):
                p=cur/fn;rel=p.relative_to(self.source);rel_s=rel.as_posix();tree.append('%s    %s'%(indent,fn))
                if p.suffix.lower()!='.ini':ignored.append((rel_s,'not ini'));continue
                try:st=p.stat();size=st.st_size;mt=getattr(st,'st_mtime_ns',int(st.st_mtime*1e9))
                except Exception as e:size=0;mt=0;self.warn(rel_s,'stat',repr(e))
                old=self.old_cache.get(rel_s,{}) if self.incremental else {};text=enc=None;sha1=''
                if old and old.get('size')==size and old.get('mtime_ns')==mt and 'text' in old:
                    text=old['text'];enc=old.get('encoding');sha1=old.get('sha1','');hits+=1
                else:
                    text,enc,err=safe_read_text(p)
                    if text is None:self.warn(rel_s,'read',err or 'read failed','ignored');ignored.append((rel_s,'unreadable'));continue
                    sha1,err2=sha1_file(p);misses+=1
                    if err2:self.warn(rel_s,'sha1',err2,'blank sha1')
                self.new_cache[rel_s]={'size':size,'mtime_ns':mt,'encoding':enc,'sha1':sha1,'text':text}
                sections,entries,comments=parse_ini_text(text);module=classify_module(rel)
                recs.append({'path':p,'rel':rel,'rel_s':rel_s,'size':size,'encoding':enc,'sha1':sha1,'text':text,'module':module,'sections':sections,'entries':entries})
        (self.output/'00_CLIENT_INI_TREE.txt').write_text('\n'.join(tree),encoding='utf-8')
        self.log('%d INI files | cache hit %d | đọc lại %d'%(len(recs),hits,misses),15)

        self.log('2/8 Lập index section/key/value',25)
        manifests=[];sections_rows=[];key_rows=[];all_occ=defaultdict(list);subsystem_files=defaultdict(set);type_counts=Counter()
        for r in recs:
            manifests.append((r['rel_s'],r['module'],r['size'],r['encoding'],r['sha1'],len(r['sections']),len(r['entries'])))
            for sec,line in r['sections']:sections_rows.append((sec,r['module'],r['rel_s'],line))
            for e in r['entries']:
                ss=classify_client_subsystem(r['rel_s'],e['section'],e['key']);subsystem_files[ss].add(r['rel_s']);type_counts[e['value_type']]+=1
                row=(e['section'],e['key'],e['value'],e['value_type'],ss,r['module'],r['rel_s'],e['line'],e['duplicate_ordinal'])
                key_rows.append(row);all_occ[(e['section'].lower(),e['key'].lower())].append((r,e,ss))
        write_tsv(self.output/'01_CLIENT_INI_MANIFEST.tsv',['relative_path','module','size_bytes','encoding','sha1','sections','keys'],manifests)
        write_tsv(self.output/'02_INI_SECTION_INDEX.tsv',['section','module','file','line'],sections_rows)
        write_tsv(self.output/'03_INI_KEY_INDEX.tsv',['section','key','value','value_type','subsystem','module','file','line','duplicate_ordinal'],key_rows)

        self.log('3/8 Cross-reference / duplicates / conflicts',40)
        refs=[];dupes=[];conflicts=[]
        for ident,items in all_occ.items():
            sec,key=ident
            values=defaultdict(list)
            for r,e,ss in items:values[e['value']].append((r,e,ss))
            if len(items)>1:
                for r,e,ss in items:refs.append((e['section'],e['key'],len(items),len(values),e['value'],ss,r['rel_s'],e['line']))
            local=defaultdict(list)
            for r,e,ss in items:local[r['rel_s']].append(e)
            for file,es in local.items():
                if len(es)>1:
                    for e in es:dupes.append((e['section'],e['key'],file,e['line'],e['value'],e['duplicate_ordinal']))
            if len(values)>1:
                conflicts.append((items[0][1]['section'],items[0][1]['key'],len(items),len(values),' | '.join(sorted(values.keys())[:12])))
        write_tsv(self.output/'04_INI_KEY_REFERENCES.tsv',['section','key','occurrences','distinct_values','value','subsystem','file','line'],refs)
        write_tsv(self.output/'05_INI_DUPLICATE_KEYS.tsv',['section','key','file','line','value','ordinal'],dupes)
        write_tsv(self.output/'06_INI_CROSS_FILE_CONFLICTS.tsv',['section','key','occurrences','distinct_values','values_preview'],conflicts)

        self.log('4/8 Resource/path references + subsystem map',52)
        path_refs=[];file_by_name=defaultdict(list)
        for r in recs:file_by_name[r['path'].name.lower()].append(r['rel_s'])
        for r in recs:
            for e in r['entries']:
                if e['value_type'] in ('path_or_file','ip_or_endpoint'):
                    target=e['value'].strip().strip('\"').strip("'");resolved=''
                    if e['value_type']=='path_or_file':
                        cand=(r['path'].parent/target).resolve() if target else None
                        try:
                            if cand and cand.exists():resolved=str(cand)
                        except Exception:pass
                        if not resolved and Path(target).name.lower() in file_by_name:resolved=';'.join(file_by_name[Path(target).name.lower()])
                    path_refs.append((e['section'],e['key'],e['value'],e['value_type'],r['rel_s'],e['line'],resolved))
        write_tsv(self.output/'07_INI_VALUE_REFERENCES.tsv',['section','key','value','value_type','file','line','resolved_or_candidate'],path_refs)
        subsystem_rows=[]
        for ss,files in sorted(subsystem_files.items()):
            for f in sorted(files):subsystem_rows.append((ss,f))
        write_tsv(self.output/'08_CLIENT_SUBSYSTEM_MAP.tsv',['subsystem','file'],subsystem_rows)

        self.log('5/8 Feature entry points + schema intelligence',64)
        entry=[];schema=[]
        feature_words=('enable','use','show','hide','width','height','resolution','fullscreen','window','quality','filter','lod','gamma','brightness','volume','server','host','port','ip','path','file','debug','language','fps','vsync')
        for r in recs:
            for e in r['entries']:
                ss=classify_client_subsystem(r['rel_s'],e['section'],e['key']);hay=(e['section']+' '+e['key']).lower();score=sum(1 for w in feature_words if w in hay)
                if score:entry.append((score,ss,e['section'],e['key'],e['value'],e['value_type'],r['rel_s'],e['line']))
        for ident,items in all_occ.items():
            types=sorted(set(e['value_type'] for r,e,ss in items));vals=sorted(set(e['value'] for r,e,ss in items))
            schema.append((items[0][1]['section'],items[0][1]['key'],len(items),','.join(types),len(vals),' | '.join(vals[:8])))
        entry.sort(key=lambda x:(-x[0],x[1],x[6],x[7]));schema.sort(key=lambda x:(x[0].lower(),x[1].lower()))
        write_tsv(self.output/'09_CLIENT_FEATURE_ENTRY_POINTS.tsv',['score','subsystem','section','key','value','value_type','file','line'],entry)
        write_tsv(self.output/'10_INI_SCHEMA_SUMMARY.tsv',['section','key','occurrences','value_types','distinct_values','values_preview'],schema)

        self.log('6/8 Đóng gói INI + AI_PACKS',76)
        modules=defaultdict(list)
        for r in recs:modules[r['module']].append(r)
        pkg=[];root=self.output/'INI_MODULES';root.mkdir(parents=True,exist_ok=True)
        def package_group(base,name,rows,label,pkgout):
            d=base/Path(*[clean_name(x) for x in name.split('/')]);d.mkdir(parents=True,exist_ok=True);part=1;cur=[];cb=0;cnt=0
            def flush():
                nonlocal part,cur,cb,cnt
                if not cur:return
                fp=d/('part_%03d.md'%part);fp.write_text('# %s: %s\n# PART: %03d\n# FILE COUNT: %d\n\n%s'%(label,name,part,cnt,''.join(cur)),encoding='utf-8');pkgout.append((name,fp.relative_to(self.output).as_posix(),cnt));part+=1;cur=[];cb=0;cnt=0
            for r in sorted(rows,key=lambda x:x['rel_s'].lower()):
                block='\n\n'+'='*100+'\nFILE: %s\nMODULE: %s\nENCODING: %s\n'% (r['rel_s'],r['module'],r['encoding'])+'='*100+'\n\n```ini\n'+r['text']+('' if r['text'].endswith('\n') else '\n')+'```\n';b=len(block.encode('utf-8'))
                if cur and cb+b>self.max_bytes:flush()
                cur.append(block);cb+=b;cnt+=1
            flush()
        for m in sorted(modules,key=str.lower):package_group(root,m,modules[m],'INI MODULE',pkg)
        write_tsv(self.output/'11_INI_PACKAGE_INDEX.tsv',['module','package','files'],pkg)
        ai_idx=[];airoot=self.output/'AI_PACKS';airoot.mkdir(parents=True,exist_ok=True)
        for ss,files in sorted(subsystem_files.items()):
            rows=[r for r in recs if r['rel_s'] in files];local=[];package_group(airoot,ss,rows,'CLIENT INI AI PACK',local);ai_idx.extend((ss,p,c) for n,p,c in local)
            d=airoot/clean_name(ss);(d/'00_MAP.md').write_text('# CLIENT INI SUBSYSTEM: %s\n\nFiles: %d\n\n%s'%(ss,len(rows),'\n'.join('- `%s`'%r['rel_s'] for r in sorted(rows,key=lambda x:x['rel_s'].lower()))),encoding='utf-8')
        write_tsv(self.output/'12_CLIENT_AI_PACK_INDEX.tsv',['subsystem','package','files'],ai_idx)

        self.log('7/8 AI bootstrap / stats / guide',88)
        stats={'version':VERSION,'mode':'client_ini','scan_time':datetime.now().isoformat(timespec='seconds'),'source_root':str(self.source.resolve()),'ini_files':len(recs),'sections':len(sections_rows),'keys':len(key_rows),'duplicate_key_rows':len(dupes),'cross_file_conflicts':len(conflicts),'value_types':dict(type_counts),'subsystems':{k:len(v) for k,v in subsystem_files.items()},'max_package_bytes':self.max_bytes}
        (self.output/'13_CLIENT_INI_STATS.json').write_text(json.dumps(stats,ensure_ascii=False,indent=2),encoding='utf-8')
        boot=['# JX CLIENT INI — AI BOOTSTRAP\n\n','This scan is optimized for AI-first investigation of JX/SwordOnline client configuration.\n\n','## AI investigation workflow\n\n','1. Start from `08_CLIENT_SUBSYSTEM_MAP.tsv` and `09_CLIENT_FEATURE_ENTRY_POINTS.tsv`.\n','2. Use `03_INI_KEY_INDEX.tsv` to locate exact section/key/value/file/line.\n','3. Check `04_INI_KEY_REFERENCES.tsv`, `05_INI_DUPLICATE_KEYS.tsv`, and `06_INI_CROSS_FILE_CONFLICTS.tsv` before changing a key that appears in multiple places.\n','4. Use `07_INI_VALUE_REFERENCES.tsv` for path/file/network-style values.\n','5. Read exact configuration context from `AI_PACKS/<SUBSYSTEM>/` or `INI_MODULES/`.\n','6. Treat indexes as navigation aids; preserve comments/order and verify behavior against the original INI package before editing.\n\n','## Detected subsystems\n\n']
        for ss,c in sorted(((k,len(v)) for k,v in subsystem_files.items()),key=lambda x:(-x[1],x[0])):boot.append('- `%s`: %d files\n'%(ss,c))
        (self.output/'AI_CLIENT_BOOTSTRAP.md').write_text(''.join(boot),encoding='utf-8')
        (self.output/'AI_CLIENT_READ_ORDER.md').write_text('# AI READ ORDER — CLIENT INI\n\n1. `AI_CLIENT_BOOTSTRAP.md`\n2. `13_CLIENT_INI_STATS.json`\n3. `08_CLIENT_SUBSYSTEM_MAP.tsv`\n4. `09_CLIENT_FEATURE_ENTRY_POINTS.tsv`\n5. `03_INI_KEY_INDEX.tsv`\n6. `04_INI_KEY_REFERENCES.tsv`\n7. `06_INI_CROSS_FILE_CONFLICTS.tsv`\n8. `10_INI_SCHEMA_SUMMARY.tsv`\n\nThen upload only requested files from `AI_PACKS` or `INI_MODULES`.\n',encoding='utf-8')
        (self.output/'14_CLIENT_AI_GUIDE.md').write_text('# CLIENT INI AI SOURCE GUIDE\n\nAI-first path: feature → subsystem → section/key → references/conflicts → exact INI package. The scanner never assumes which value wins at runtime; source order and client code determine precedence and must be verified when critical.\n',encoding='utf-8')
        write_tsv(self.output/'98_CLIENT_INI_SCAN_WARNINGS.tsv',['file','stage','error','action'],self.warnings)
        with (self.output/'99_CLIENT_INI_IGNORED_FILES.txt').open('w',encoding='utf-8') as f:
            for rel,why in ignored:f.write('[%s] %s\n'%(why,rel))
        try:self.cache_path.write_text(json.dumps(self.new_cache,ensure_ascii=False),encoding='utf-8')
        except Exception as e:self.warn(self.cache_path.name,'save_cache',repr(e),'cache not saved')

        self.log('8/8 CHATGPT_UPLOADED',95)
        starter=['AI_CLIENT_BOOTSTRAP.md','AI_CLIENT_READ_ORDER.md','13_CLIENT_INI_STATS.json','08_CLIENT_SUBSYSTEM_MAP.tsv','09_CLIENT_FEATURE_ENTRY_POINTS.tsv','03_INI_KEY_INDEX.tsv','04_INI_KEY_REFERENCES.tsv','06_INI_CROSS_FILE_CONFLICTS.tsv','10_INI_SCHEMA_SUMMARY.tsv','14_CLIENT_AI_GUIDE.md']
        copied=build_chatgpt_uploaded(self.output,starter,'CHATGPT FIRST-UPLOAD BUNDLE — JX CLIENT INI',[
            'Upload this folder first when asking ChatGPT to understand or modify JX client configuration.',
            'Full INI source packages remain in the parent INI_MODULES and AI_PACKS folders.'
        ])
        self.log('CHATGPT_UPLOADED: %d file khởi tạo AI'%len(copied));self.log('Hoàn tất Client INI scan trong %.2f giây'%(time.time()-started),100)
        return stats


class TxtNpcResScanner:
    """AI-first scanner dedicated to legacy JX npcres/settings .txt folders."""
    def __init__(self,source,output,max_bytes,incremental,clean_generated,cancel_event,emit):
        self.source=source;self.output=output;self.max_bytes=max_bytes;self.incremental=incremental;self.clean_generated=clean_generated;self.cancel_event=cancel_event;self.emit=emit;self.warnings=[]
        self.cache_path=output/'.jxsi_txt_cache.json';self.old_cache={};self.new_cache={}
    def cancelled(self):
        if self.cancel_event.is_set():raise RuntimeError('__CANCELLED__')
    def log(self,msg,progress=None):self.emit(('log',msg,progress))
    def warn(self,rel,stage,err,action='continued'):self.warnings.append((rel,stage,err,action))
    def load_cache(self):
        if self.incremental and self.cache_path.exists():
            try:self.old_cache=json.loads(self.cache_path.read_text(encoding='utf-8'))
            except Exception as e:self.warn(self.cache_path.name,'load_cache',repr(e),'ignored cache')
    def clean_output(self):
        if not self.clean_generated:return
        for name in ('TXT_MODULES','AI_PACKS','CHATGPT_UPLOADED'):
            p=self.output/name
            if p.exists():
                try:shutil.rmtree(str(p))
                except Exception as e:self.warn(name,'clean_output',repr(e),'left old directory')
        for p in self.output.glob('*'):
            if p.is_file() and (p.name.startswith(('00_','01_','02_','03_','04_','05_','06_','07_','08_','09_','10_','11_','12_','13_','14_','15_','98_','99_','AI_'))):
                try:p.unlink()
                except Exception as e:self.warn(p.name,'clean_output',repr(e),'left old file')
    @staticmethod
    def split_row(line):
        if '\t' in line:return line.split('\t'),'TAB'
        if ',' in line:return line.split(','),'COMMA'
        return [line],'TEXT'
    @staticmethod
    def refs_in_line(line):
        # Keep resource strings exactly as written; normalization is a separate field.
        rx=re.compile(r'(?i)([^\t,;"\'<>|]*?\.(?:spr|wav|mp3|ogg|bmp|jpg|jpeg|png|pak|txt))')
        out=[]
        for m in rx.finditer(line):
            raw=m.group(1).strip().strip('"\'')
            if raw:out.append(raw)
        return out
    def scan(self):
        started=time.time();self.output.mkdir(parents=True,exist_ok=True);self.load_cache();self.clean_output()
        self.log('NPCRES TXT SOURCE : %s'%self.source.resolve());self.log('NPCRES TXT OUTPUT : %s'%self.output.resolve())
        tree=[str(self.source.resolve())];recs=[];ignored=[];hits=0;misses=0;out_resolved=self.output.resolve()
        self.log('1/7 Quét riêng file .txt',5)
        for cr,dirs,files in os.walk(str(self.source)):
            self.cancelled();cur=Path(cr);rel_dir=cur.relative_to(self.source);filtered=[]
            for d in dirs:
                dp=cur/d
                try:
                    if is_subpath(dp,out_resolved) or dp.resolve()==out_resolved:continue
                except Exception:pass
                filtered.append(d)
            dirs[:]=filtered;indent='    '*len(rel_dir.parts)
            if rel_dir.parts:tree.append('%s[DIR] %s/'%(indent,rel_dir.as_posix()))
            for fn in sorted(files):
                p=cur/fn;rel=p.relative_to(self.source);rel_s=rel.as_posix();tree.append('%s    %s'%(indent,fn))
                if p.suffix.lower()!='.txt':ignored.append((rel_s,'not txt'));continue
                try:st=p.stat();size=st.st_size;mt=getattr(st,'st_mtime_ns',int(st.st_mtime*1e9))
                except Exception as e:size=0;mt=0;self.warn(rel_s,'stat',repr(e))
                old=self.old_cache.get(rel_s,{}) if self.incremental else {};text=enc=None;sha1=''
                if old and old.get('size')==size and old.get('mtime_ns')==mt and 'text' in old:
                    text=old['text'];enc=old.get('encoding');sha1=old.get('sha1','');hits+=1
                else:
                    text,enc,err=safe_read_text(p)
                    if text is None:self.warn(rel_s,'read',err or 'read failed','ignored');ignored.append((rel_s,'unreadable'));continue
                    sha1,err2=sha1_file(p);misses+=1
                    if err2:self.warn(rel_s,'sha1',err2,'blank sha1')
                self.new_cache[rel_s]={'size':size,'mtime_ns':mt,'encoding':enc,'sha1':sha1,'text':text}
                recs.append({'path':p,'rel':rel,'rel_s':rel_s,'size':size,'encoding':enc,'sha1':sha1,'text':text,'module':classify_module(rel)})
        (self.output/'00_NPCRES_TXT_TREE.txt').write_text('\n'.join(tree),encoding='utf-8')
        self.log('%d TXT files | cache hit %d | đọc lại %d'%(len(recs),hits,misses),18)

        self.log('2/7 Lập manifest + cấu trúc dòng/cột',30)
        manifest=[];rows=[];refs=[];name_index=defaultdict(list);ref_index=defaultdict(list)
        for r in recs:
            lines=r['text'].splitlines();nonempty=0;maxcols=0;delims=Counter();comment_lines=0
            for ln,line in enumerate(lines,1):
                self.cancelled();st=line.strip()
                if not st:continue
                nonempty+=1
                if st.startswith(('#',';','//')):comment_lines+=1;continue
                cols,delim=self.split_row(line);delims[delim]+=1;maxcols=max(maxcols,len(cols))
                preview=' | '.join(x.strip() for x in cols[:12])[:1000]
                rows.append((r['rel_s'],ln,delim,len(cols),preview))
                for ci,val in enumerate(cols,1):
                    v=val.strip()
                    if v:name_index[v.lower()].append((r['rel_s'],ln,ci,v))
                for raw in self.refs_in_line(line):
                    norm=norm_rel(raw.strip().lstrip('./'))
                    ext=Path(raw.replace('\\','/')).suffix.lower()
                    refs.append((raw,norm,ext,r['rel_s'],ln,line.strip()[:1000]));ref_index[norm].append((r['rel_s'],ln,raw))
            manifest.append((r['rel_s'],r['module'],r['size'],r['encoding'],r['sha1'],len(lines),nonempty,maxcols,delims.most_common(1)[0][0] if delims else 'TEXT',comment_lines))
        write_tsv(self.output/'01_NPCRES_TXT_MANIFEST.tsv',['relative_path','module','size_bytes','encoding','sha1','lines','nonempty_lines','max_columns','dominant_format','comment_lines'],manifest)
        write_tsv(self.output/'02_NPCRES_ROW_INDEX.tsv',['file','line','format','column_count','row_preview'],rows)
        write_tsv(self.output/'03_NPCRES_RESOURCE_REFERENCES.tsv',['resource_raw','resource_normalized','extension','file','line','context'],refs)

        self.log('3/7 Resource cross-reference + duplicate intelligence',45)
        cross=[]
        for norm,items in sorted(ref_index.items()):
            for f,l,raw in items:cross.append((norm,len(items),len(set(x[0] for x in items)),raw,f,l))
        write_tsv(self.output/'04_NPCRES_RESOURCE_XREF.tsv',['resource_normalized','occurrences','files','resource_raw','file','line'],cross)
        duplicate_rows=[]
        for key,items in name_index.items():
            if len(items)>1:
                # Useful for IDs/names repeated across npcres tables without assuming a schema.
                for f,l,c,v in items:duplicate_rows.append((v,len(items),f,l,c))
        write_tsv(self.output/'05_NPCRES_REPEATED_VALUES.tsv',['value','occurrences','file','line','column'],duplicate_rows)

        self.log('4/7 Tạo fingerprint phục vụ mapping gốc ↔ Phong Thần',58)
        fingerprints=[]
        for r in recs:
            resource_set=sorted(set(norm_rel(x) for line in r['text'].splitlines() for x in self.refs_in_line(line)))
            content_norm='\n'.join(' '.join(x.strip().lower().split()) for x in r['text'].splitlines() if x.strip() and not x.strip().startswith(('#',';','//')))
            struct=[]
            for line in r['text'].splitlines():
                if not line.strip():continue
                cols,delim=self.split_row(line);struct.append('%s:%d'%(delim,len(cols)))
            fingerprints.append((r['rel_s'],r['path'].name,r['sha1'],hashlib.sha1(content_norm.encode('utf-8')).hexdigest(),hashlib.sha1('|'.join(struct).encode('utf-8')).hexdigest(),len(resource_set),';'.join(resource_set[:80])))
        write_tsv(self.output/'06_NPCRES_MAPPING_FINGERPRINTS.tsv',['file','basename','raw_sha1','normalized_content_sha1','structure_sha1','unique_resources','resource_preview'],fingerprints)

        self.log('5/7 Đóng gói TXT nguyên văn cho ChatGPT',70)
        root=self.output/'TXT_MODULES';root.mkdir(parents=True,exist_ok=True);pkg=[];part=1;cur=[];cb=0;cnt=0
        def flush():
            nonlocal part,cur,cb,cnt
            if not cur:return
            fp=root/('part_%03d.md'%part);fp.write_text('# NPCRES TXT PACKAGE\n# PART: %03d\n# FILE COUNT: %d\n\n%s'%(part,cnt,''.join(cur)),encoding='utf-8');pkg.append((fp.relative_to(self.output).as_posix(),cnt,cb));part+=1;cur=[];cb=0;cnt=0
        for r in sorted(recs,key=lambda x:x['rel_s'].lower()):
            block='\n\n'+'='*100+'\nFILE: %s\nENCODING: %s\nSHA1: %s\n'%(r['rel_s'],r['encoding'],r['sha1'])+'='*100+'\n\n```text\n'+r['text']+('' if r['text'].endswith('\n') else '\n')+'```\n';b=len(block.encode('utf-8'))
            if cur and cb+b>self.max_bytes:flush()
            cur.append(block);cb+=b;cnt+=1
        flush();write_tsv(self.output/'07_NPCRES_PACKAGE_INDEX.tsv',['package','files','bytes'],pkg)

        self.log('6/7 AI bootstrap / mapping guide',84)
        stats={'version':VERSION,'mode':'npcres_txt','scan_time':datetime.now().isoformat(timespec='seconds'),'source_root':str(self.source.resolve()),'txt_files':len(recs),'rows_indexed':len(rows),'resource_references':len(refs),'unique_resources':len(ref_index),'repeated_value_rows':len(duplicate_rows),'max_package_bytes':self.max_bytes,'cache_hits':hits,'cache_misses':misses,'warnings':len(self.warnings)}
        (self.output/'08_NPCRES_TXT_STATS.json').write_text(json.dumps(stats,ensure_ascii=False,indent=2),encoding='utf-8')
        boot=['# JX NPCRES TXT — AI BOOTSTRAP\n\n','Dedicated AI-first scan for comparing/restoring JX npcres TXT data. No schema is assumed unless the TXT itself proves it.\n\n','## Recommended mapping workflow\n\n','1. Upload this CHATGPT_UPLOADED bundle from BOTH `npcres_phongthan` and `npcres_goc`.\n','2. Start with `01_NPCRES_TXT_MANIFEST.tsv` and `06_NPCRES_MAPPING_FINGERPRINTS.tsv` to pair same/renamed/structurally related files.\n','3. Use `03_NPCRES_RESOURCE_REFERENCES.tsv` and `04_NPCRES_RESOURCE_XREF.tsv` to trace `.spr` and other resource paths.\n','4. Use `02_NPCRES_ROW_INDEX.tsv` for exact file/line/column shape before deciding how IDs map.\n','5. Request exact `TXT_MODULES/part_XXX.md` only when full rows are needed.\n','6. Preserve the working server IDs first; restore VinaGame/JX presentation by verified mapping rather than blind file replacement.\n\n','## Scan summary\n\n','- TXT files: **%d**\n- Indexed rows: **%d**\n- Resource references: **%d**\n- Unique normalized resources: **%d**\n'%(len(recs),len(rows),len(refs),len(ref_index))]
        (self.output/'AI_NPCRES_BOOTSTRAP.md').write_text(''.join(boot),encoding='utf-8')
        (self.output/'AI_NPCRES_READ_ORDER.md').write_text('# AI READ ORDER — NPCRES TXT\n\n1. `AI_NPCRES_BOOTSTRAP.md`\n2. `08_NPCRES_TXT_STATS.json`\n3. `01_NPCRES_TXT_MANIFEST.tsv`\n4. `06_NPCRES_MAPPING_FINGERPRINTS.tsv`\n5. `03_NPCRES_RESOURCE_REFERENCES.tsv`\n6. `04_NPCRES_RESOURCE_XREF.tsv`\n7. `02_NPCRES_ROW_INDEX.tsv`\n\nThen upload only requested `TXT_MODULES/part_XXX.md`. For restoration, scan both PhongThan and original/VinaGame npcres folders separately and give ChatGPT both first-upload bundles.\n',encoding='utf-8')
        write_tsv(self.output/'98_NPCRES_SCAN_WARNINGS.tsv',['file','stage','error','action'],self.warnings)
        with (self.output/'99_NPCRES_IGNORED_FILES.txt').open('w',encoding='utf-8') as f:
            for rel,why in ignored:f.write('[%s] %s\n'%(why,rel))
        try:self.cache_path.write_text(json.dumps(self.new_cache,ensure_ascii=False),encoding='utf-8')
        except Exception as e:self.warn(self.cache_path.name,'save_cache',repr(e),'cache not saved')

        self.log('7/7 CHATGPT_UPLOADED',95)
        starter=['AI_NPCRES_BOOTSTRAP.md','AI_NPCRES_READ_ORDER.md','08_NPCRES_TXT_STATS.json','01_NPCRES_TXT_MANIFEST.tsv','06_NPCRES_MAPPING_FINGERPRINTS.tsv','03_NPCRES_RESOURCE_REFERENCES.tsv','04_NPCRES_RESOURCE_XREF.tsv','02_NPCRES_ROW_INDEX.tsv']
        copied=build_chatgpt_uploaded(self.output,starter,'CHATGPT FIRST-UPLOAD BUNDLE — JX NPCRES TXT',[
            'Scan npcres_phongthan and npcres_goc/VinaGame separately, then upload both CHATGPT_UPLOADED folders first.',
            'The full original TXT content remains packaged under TXT_MODULES and is only needed when ChatGPT asks for exact rows.'
        ])
        self.log('CHATGPT_UPLOADED: %d file khởi tạo AI'%len(copied));self.log('Hoàn tất NPCRES TXT scan trong %.2f giây'%(time.time()-started),100)
        return stats

class App:
    def __init__(self,root):
        self.root=root;root.title('%s v%s'%(APP_TITLE,VERSION));root.geometry('1120x860')
        self.q=queue.Queue();self.worker=None;self.cancel_event=threading.Event();self.active_mode=None
        self.cpp_src=tk.StringVar();self.cpp_out=tk.StringVar();self.cpp_maxmb=tk.StringVar(value='4')
        self.cpp_dep=tk.BooleanVar(value=False);self.cpp_unknown=tk.BooleanVar(value=False);self.cpp_ai_packs=tk.BooleanVar(value=True);self.cpp_incremental=tk.BooleanVar(value=True);self.cpp_clean=tk.BooleanVar(value=True)
        self.lua_src=tk.StringVar();self.lua_out=tk.StringVar();self.lua_maxmb=tk.StringVar(value='4');self.lua_incremental=tk.BooleanVar(value=True);self.lua_clean=tk.BooleanVar(value=True)
        self.client_src=tk.StringVar();self.client_out=tk.StringVar();self.client_maxmb=tk.StringVar(value='12');self.client_hash_all=tk.BooleanVar(value=False);self.client_scan_text=tk.BooleanVar(value=True);self.client_native_extract=tk.BooleanVar(value=True)
        self.txt_src=tk.StringVar();self.txt_out=tk.StringVar();self.txt_maxmb=tk.StringVar(value='4');self.txt_incremental=tk.BooleanVar(value=True);self.txt_clean=tk.BooleanVar(value=True)
        self.status=tk.StringVar(value='Sẵn sàng');self.prog=tk.DoubleVar(value=0)
        self.ui();self.root.after(100,self.poll_queue)

    def path_row(self,parent,row,label,var,pickcmd):
        ttk.Label(parent,text=label).grid(row=row,column=0,sticky='w')
        ttk.Entry(parent,textvariable=var).grid(row=row+1,column=0,sticky='ew',padx=(0,8))
        ttk.Button(parent,text='Chọn...',command=pickcmd).grid(row=row+1,column=1)

    def ui(self):
        ttk.Label(self.root,text=APP_TITLE,font=('Segoe UI',18,'bold')).pack(pady=(10,2))
        ttk.Label(self.root,text='v3.3 — C/C++ • Lua • Workshop V4.3 Client/Resource • NPCRES TXT').pack()
        self.nb=ttk.Notebook(self.root);self.nb.pack(fill='both',expand=True,padx=10,pady=8)
        self.cpp_tab=ttk.Frame(self.nb);self.lua_tab=ttk.Frame(self.nb);self.client_tab=ttk.Frame(self.nb);self.txt_tab=ttk.Frame(self.nb);self.nb.add(self.cpp_tab,text='C/C++ SOURCE');self.nb.add(self.lua_tab,text='LUA SCRIPT');self.nb.add(self.client_tab,text='CLIENT / RESOURCE');self.nb.add(self.txt_tab,text='NPCRES TXT')
        self.build_cpp_tab();self.build_lua_tab();self.build_client_tab();self.build_txt_tab()
        bottom=ttk.Frame(self.root);bottom.pack(fill='x',padx=12,pady=(0,8))
        ttk.Progressbar(bottom,variable=self.prog,maximum=100).pack(fill='x');ttk.Label(bottom,textvariable=self.status).pack(anchor='w',pady=3)

    def common_log(self,parent):
        lf=ttk.LabelFrame(parent,text='Log');lf.pack(fill='both',expand=True,padx=10,pady=8)
        t=tk.Text(lf,font=('Consolas',9),wrap='word');t.pack(fill='both',expand=True);return t

    def build_cpp_tab(self):
        f=ttk.Frame(self.cpp_tab);f.pack(fill='x',padx=10,pady=8);f.columnconfigure(0,weight=1)
        self.path_row(f,0,'Source JX C/C++:',self.cpp_src,self.pick_cpp_src);self.path_row(f,2,'Output C/C++:',self.cpp_out,self.pick_cpp_out)
        o=ttk.LabelFrame(self.cpp_tab,text='Tùy chọn C/C++');o.pack(fill='x',padx=10,pady=4)
        ttk.Checkbutton(o,text='Bao gồm DirectX / ThirdParty / SDK',variable=self.cpp_dep).grid(row=0,column=0,sticky='w',padx=10,pady=3)
        ttk.Checkbutton(o,text='Thử đọc file text chưa biết extension',variable=self.cpp_unknown).grid(row=1,column=0,sticky='w',padx=10,pady=3)
        ttk.Checkbutton(o,text='Tạo AI_PACKS theo subsystem',variable=self.cpp_ai_packs).grid(row=0,column=1,sticky='w',padx=20,pady=3)
        ttk.Checkbutton(o,text='Incremental scan / cache',variable=self.cpp_incremental).grid(row=1,column=1,sticky='w',padx=20,pady=3)
        ttk.Checkbutton(o,text='Dọn generated output cũ',variable=self.cpp_clean).grid(row=2,column=1,sticky='w',padx=20,pady=3)
        r=ttk.Frame(o);r.grid(row=2,column=0,sticky='w',padx=10,pady=4);ttk.Label(r,text='Package tối đa:').pack(side='left');ttk.Entry(r,textvariable=self.cpp_maxmb,width=7).pack(side='left',padx=5);ttk.Label(r,text='MB').pack(side='left')
        ttk.Label(self.cpp_tab,text='Giữ toàn bộ chức năng v3 + tự tạo CHATGPT_UPLOADED chứa bộ file nên upload trước.',wraplength=1040).pack(padx=10,pady=4)
        b=ttk.Frame(self.cpp_tab);b.pack(fill='x',padx=10,pady=4)
        self.cpp_start=ttk.Button(b,text='BẮT ĐẦU SCAN C/C++',command=self.start_cpp);self.cpp_start.pack(side='left')
        self.cpp_cancel=ttk.Button(b,text='HỦY',command=self.cancel_scan,state='disabled');self.cpp_cancel.pack(side='left',padx=8)
        ttk.Button(b,text='Mở output',command=lambda:self.open_path(self.cpp_out)).pack(side='left',padx=8)
        ttk.Button(b,text='Mở CHATGPT_UPLOADED',command=lambda:self.open_chatgpt(self.cpp_out)).pack(side='left',padx=8)
        self.cpp_log=self.common_log(self.cpp_tab)

    def build_lua_tab(self):
        f=ttk.Frame(self.lua_tab);f.pack(fill='x',padx=10,pady=8);f.columnconfigure(0,weight=1)
        self.path_row(f,0,'Source Lua Script:',self.lua_src,self.pick_lua_src);self.path_row(f,2,'Output Lua:',self.lua_out,self.pick_lua_out)
        o=ttk.LabelFrame(self.lua_tab,text='Tùy chọn Lua');o.pack(fill='x',padx=10,pady=4)
        ttk.Checkbutton(o,text='Incremental scan / cache Lua',variable=self.lua_incremental).grid(row=0,column=0,sticky='w',padx=10,pady=3)
        ttk.Checkbutton(o,text='Dọn generated output Lua cũ',variable=self.lua_clean).grid(row=1,column=0,sticky='w',padx=10,pady=3)
        r=ttk.Frame(o);r.grid(row=0,column=1,sticky='w',padx=20,pady=3);ttk.Label(r,text='Package tối đa:').pack(side='left');ttk.Entry(r,textvariable=self.lua_maxmb,width=7).pack(side='left',padx=5);ttk.Label(r,text='MB').pack(side='left')
        ttk.Label(self.lua_tab,text='AI-first cho Lua: function/global index • require/dofile/loadfile graph • function references • subsystem map • entry points • AI_PACKS • CHATGPT_UPLOADED.',wraplength=1040).pack(padx=10,pady=4)
        b=ttk.Frame(self.lua_tab);b.pack(fill='x',padx=10,pady=4)
        self.lua_start=ttk.Button(b,text='BẮT ĐẦU SCAN LUA',command=self.start_lua);self.lua_start.pack(side='left')
        self.lua_cancel=ttk.Button(b,text='HỦY',command=self.cancel_scan,state='disabled');self.lua_cancel.pack(side='left',padx=8)
        ttk.Button(b,text='Mở output',command=lambda:self.open_path(self.lua_out)).pack(side='left',padx=8)
        ttk.Button(b,text='Mở CHATGPT_UPLOADED',command=lambda:self.open_chatgpt(self.lua_out)).pack(side='left',padx=8)
        self.lua_log=self.common_log(self.lua_tab)

    def build_client_tab(self):
        f=ttk.Frame(self.client_tab);f.pack(fill='x',padx=10,pady=8);f.columnconfigure(0,weight=1)
        self.path_row(f,0,'Client Root:',self.client_src,self.pick_client_src);self.path_row(f,2,'Output CLIENT_MAPPING:',self.client_out,self.pick_client_out)
        o=ttk.LabelFrame(self.client_tab,text='Tùy chọn JX Workshop Client Scanner V4.3');o.pack(fill='x',padx=10,pady=4)
        ttk.Checkbutton(o,text='Hash toàn bộ file (chậm hơn)',variable=self.client_hash_all).grid(row=0,column=0,sticky='w',padx=10,pady=3)
        ttk.Checkbutton(o,text='Scan text/config để thu virtual resource paths',variable=self.client_scan_text).grid(row=1,column=0,sticky='w',padx=10,pady=3)
        ttk.Checkbutton(o,text='Native extract tài nguyên character/NPCRes từ PAK',variable=self.client_native_extract).grid(row=0,column=1,sticky='w',padx=20,pady=3)
        ttk.Label(self.client_tab,text='Workshop V4.3 scanner: client tree/manifest • package.ini order • XPack index • JX FileNameToId • loose↔PAK override • NPCRes table/resource resolver • exact KNpcRes chain • native PAK extraction • resource reference graph • upload bundle.',wraplength=1040).pack(padx=10,pady=4)
        b=ttk.Frame(self.client_tab);b.pack(fill='x',padx=10,pady=4)
        self.client_start=ttk.Button(b,text='BẮT ĐẦU SCAN CLIENT / RESOURCE',command=self.start_client);self.client_start.pack(side='left')
        self.client_cancel=ttk.Button(b,text='HỦY',command=self.cancel_scan,state='disabled');self.client_cancel.pack(side='left',padx=8)
        ttk.Button(b,text='Mở output',command=lambda:self.open_path(self.client_out)).pack(side='left',padx=8)
        ttk.Button(b,text='Mở upload',command=self.open_client_upload).pack(side='left',padx=8)
        self.client_log=self.common_log(self.client_tab)

    def build_txt_tab(self):
        f=ttk.Frame(self.txt_tab);f.pack(fill='x',padx=10,pady=8);f.columnconfigure(0,weight=1)
        self.path_row(f,0,'Source npcres (.txt):',self.txt_src,self.pick_txt_src);self.path_row(f,2,'Output NPCRES TXT:',self.txt_out,self.pick_txt_out)
        o=ttk.LabelFrame(self.txt_tab,text='Tùy chọn NPCRES TXT');o.pack(fill='x',padx=10,pady=4)
        ttk.Checkbutton(o,text='Incremental scan / cache TXT',variable=self.txt_incremental).grid(row=0,column=0,sticky='w',padx=10,pady=3)
        ttk.Checkbutton(o,text='Dọn generated output TXT cũ',variable=self.txt_clean).grid(row=1,column=0,sticky='w',padx=10,pady=3)
        r=ttk.Frame(o);r.grid(row=0,column=1,sticky='w',padx=20,pady=3);ttk.Label(r,text='Package tối đa:').pack(side='left');ttk.Entry(r,textvariable=self.txt_maxmb,width=7).pack(side='left',padx=5);ttk.Label(r,text='MB').pack(side='left')
        ttk.Label(self.txt_tab,text='AI-first riêng cho npcres TXT: manifest • row/column shape • SPR/resource references • cross-reference • mapping fingerprints • TXT_MODULES • CHATGPT_UPLOADED. Scan PhongThan và gốc/VinaGame riêng để ChatGPT trace mapping.',wraplength=1040).pack(padx=10,pady=4)
        b=ttk.Frame(self.txt_tab);b.pack(fill='x',padx=10,pady=4)
        self.txt_start=ttk.Button(b,text='BẮT ĐẦU SCAN NPCRES TXT',command=self.start_txt);self.txt_start.pack(side='left')
        self.txt_cancel=ttk.Button(b,text='HỦY',command=self.cancel_scan,state='disabled');self.txt_cancel.pack(side='left',padx=8)
        ttk.Button(b,text='Mở output',command=lambda:self.open_path(self.txt_out)).pack(side='left',padx=8)
        ttk.Button(b,text='Mở CHATGPT_UPLOADED',command=lambda:self.open_chatgpt(self.txt_out)).pack(side='left',padx=8)
        self.txt_log=self.common_log(self.txt_tab)

    def pick_cpp_src(self):
        p=filedialog.askdirectory()
        if p:self.cpp_src.set(p);self.cpp_out.set(str(Path(p).parent/'JX_SOURCE_INTELLIGENCE_V3'))
    def pick_cpp_out(self):
        p=filedialog.askdirectory()
        if p:self.cpp_out.set(p)
    def pick_lua_src(self):
        p=filedialog.askdirectory()
        if p:self.lua_src.set(p);self.lua_out.set(str(Path(p).parent/'JX_LUA_INTELLIGENCE_V3'))
    def pick_lua_out(self):
        p=filedialog.askdirectory()
        if p:self.lua_out.set(p)
    def pick_client_src(self):
        p=filedialog.askdirectory()
        if p:self.client_src.set(p);self.client_out.set(str(Path(p)/'CLIENT_MAPPING'))
    def pick_client_out(self):
        p=filedialog.askdirectory()
        if p:self.client_out.set(p)
    def pick_txt_src(self):
        p=filedialog.askdirectory()
        if p:self.txt_src.set(p);self.txt_out.set(str(Path(p).parent/'JX_NPCRES_TXT_INTELLIGENCE_V3'))
    def pick_txt_out(self):
        p=filedialog.askdirectory()
        if p:self.txt_out.set(p)
    def open_path(self,var):
        p=Path(var.get().strip())
        if p.exists():os.startfile(str(p))
    def open_chatgpt(self,var):
        p=Path(var.get().strip())/'CHATGPT_UPLOADED'
        if p.exists():os.startfile(str(p))
        else:messagebox.showinfo(APP_TITLE,'Chưa có folder CHATGPT_UPLOADED. Hãy scan trước.')
    def open_client_upload(self):
        p=Path(self.client_out.get().strip())/'upload'
        if p.exists():os.startfile(str(p))
        else:messagebox.showinfo(APP_TITLE,'Chưa có folder upload. Hãy scan Client trước.')

    def set_running(self,mode,running):
        self.active_mode=mode if running else None
        self.cpp_start.config(state='disabled' if running else 'normal');self.lua_start.config(state='disabled' if running else 'normal');self.client_start.config(state='disabled' if running else 'normal');self.txt_start.config(state='disabled' if running else 'normal')
        self.cpp_cancel.config(state='normal' if running and mode=='cpp' else 'disabled');self.lua_cancel.config(state='normal' if running and mode=='lua' else 'disabled');self.client_cancel.config(state='normal' if running and mode=='client' else 'disabled');self.txt_cancel.config(state='normal' if running and mode=='txt' else 'disabled')

    def validate(self,source,output,maxmb):
        if not source.is_dir():messagebox.showerror(APP_TITLE,'Source không hợp lệ');return None
        if not str(output):messagebox.showerror(APP_TITLE,'Output không hợp lệ');return None
        try:max_bytes=int(float(maxmb)*1024*1024)
        except Exception:messagebox.showerror(APP_TITLE,'Package MB không hợp lệ');return None
        if source.resolve()==output.resolve():messagebox.showerror(APP_TITLE,'Output không được trùng Source');return None
        return max_bytes

    def start_cpp(self):
        if self.worker and self.worker.is_alive():return
        source=Path(self.cpp_src.get().strip());output=Path(self.cpp_out.get().strip());mb=self.validate(source,output,self.cpp_maxmb.get())
        if mb is None:return
        self.cpp_log.delete('1.0','end');self.prog.set(0);self.status.set('Đang phân tích C/C++...');self.cancel_event.clear();self.set_running('cpp',True)
        scanner=Scanner(source,output,mb,self.cpp_dep.get(),self.cpp_unknown.get(),self.cpp_ai_packs.get(),self.cpp_incremental.get(),self.cpp_clean.get(),self.cancel_event,self.q.put)
        self.launch(scanner,'cpp')
    def start_lua(self):
        if self.worker and self.worker.is_alive():return
        source=Path(self.lua_src.get().strip());output=Path(self.lua_out.get().strip());mb=self.validate(source,output,self.lua_maxmb.get())
        if mb is None:return
        self.lua_log.delete('1.0','end');self.prog.set(0);self.status.set('Đang phân tích Lua...');self.cancel_event.clear();self.set_running('lua',True)
        scanner=LuaScanner(source,output,mb,self.lua_incremental.get(),self.lua_clean.get(),self.cancel_event,self.q.put)
        self.launch(scanner,'lua')
    def start_client(self):
        if self.worker and self.worker.is_alive():return
        source=Path(self.client_src.get().strip());output=Path(self.client_out.get().strip())
        if not source.is_dir():messagebox.showerror(APP_TITLE,'Client Root không hợp lệ');return
        if not str(output):messagebox.showerror(APP_TITLE,'Output không hợp lệ');return
        if source.resolve()==output.resolve():messagebox.showerror(APP_TITLE,'Output không được trùng Client Root');return
        self.client_log.delete('1.0','end');self.prog.set(0);self.status.set('Đang quét Client / Resource bằng Workshop V4.3...');self.cancel_event.clear();self.set_running('client',True)
        scanner=WorkshopClientScanner(source,output,self.client_hash_all.get(),self.client_scan_text.get(),self.client_native_extract.get(),self.cancel_event,self.q.put)
        self.launch(scanner,'client')
    def start_txt(self):
        if self.worker and self.worker.is_alive():return
        source=Path(self.txt_src.get().strip());output=Path(self.txt_out.get().strip());mb=self.validate(source,output,self.txt_maxmb.get())
        if mb is None:return
        self.txt_log.delete('1.0','end');self.prog.set(0);self.status.set('Đang phân tích NPCRES TXT...');self.cancel_event.clear();self.set_running('txt',True)
        scanner=TxtNpcResScanner(source,output,mb,self.txt_incremental.get(),self.txt_clean.get(),self.cancel_event,self.q.put)
        self.launch(scanner,'txt')
    def launch(self,scanner,mode):
        def work():
            try:self.q.put(('done',mode,scanner.scan()))
            except Exception as e:
                if str(e)=='__CANCELLED__':self.q.put(('cancelled',mode,None))
                else:self.q.put(('error',mode,repr(e)))
        self.worker=threading.Thread(target=work,daemon=True);self.worker.start()
    def cancel_scan(self):self.cancel_event.set();self.status.set('Đang hủy...')
    def say(self,mode,msg):
        t=self.cpp_log if mode=='cpp' else self.lua_log if mode=='lua' else self.client_log if mode=='client' else self.txt_log;t.insert('end',msg+'\\n');t.see('end')
    def poll_queue(self):
        try:
            while True:
                item=self.q.get_nowait();kind=item[0]
                if kind=='log':
                    # Log belongs to currently active worker.
                    mode=self.active_mode or 'cpp';msg,progress=item[1],item[2];self.say(mode,msg)
                    if progress is not None:self.prog.set(progress)
                elif kind=='done':
                    mode,stats=item[1],item[2];self.set_running(None,False);self.status.set('Hoàn tất');self.prog.set(100);self.say(mode,'Hoàn tất. CHATGPT_UPLOADED đã được tạo.')
                    if mode=='cpp':messagebox.showinfo(APP_TITLE,'C/C++ scan hoàn tất.\\n\\nHãy upload folder CHATGPT_UPLOADED trước khi yêu cầu ChatGPT điều tra/build tính năng mới.')
                    else:messagebox.showinfo(APP_TITLE,'Lua scan hoàn tất.\\n\\nHãy upload folder CHATGPT_UPLOADED trước khi yêu cầu ChatGPT điều tra/chỉnh sửa Lua.')
                elif kind=='cancelled':
                    mode=item[1];self.set_running(None,False);self.status.set('Đã hủy');self.say(mode,'Đã hủy theo yêu cầu.')
                elif kind=='error':
                    mode,err=item[1],item[2];self.set_running(None,False);self.status.set('Lỗi');self.say(mode,'ERROR: '+err);messagebox.showerror(APP_TITLE,'Scanner gặp lỗi:\\n'+err)
        except queue.Empty:pass
        self.root.after(100,self.poll_queue)

if __name__=='__main__':
    root=tk.Tk();App(root);root.mainloop()
