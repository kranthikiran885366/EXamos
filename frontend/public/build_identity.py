from pathlib import Path
import re, json, subprocess, zipfile, math
from reportlab.pdfgen import canvas
from reportlab.lib.colors import HexColor
from reportlab.lib.utils import ImageReader
from PIL import Image
B=Path('/workspace/scratch/5ec5e18aca44/SPPIO_Identity'); B.mkdir(exist_ok=True)
INK='#302337'; ACC='#B54F34'; PAPER='#F6F2ED'; WHITE='#FFFFFF'; MUT='#756F79'; LINE='#DCD5D2'
# One source of geometry; no font objects in any master.
icon=['M 0 30 L 30 0 L 78 0 L 60 18 L 36 18 L 18 36 L 18 72 L 0 90 Z','M 28 100 L 46 82 L 70 82 L 82 70 L 82 28 L 100 10 L 100 76 L 76 100 Z']
S='M 70 8 C 58 1 49 -2 36 -2 C 14 -2 1 10 1 27 C 1 43 12 51 32 57 L 42 60 C 54 64 59 69 59 76 C 59 84 51 89 40 89 C 27 89 17 84 7 77 L 0 91 C 12 100 25 104 40 104 C 63 104 78 93 78 75 C 78 59 68 50 49 44 L 37 40 C 24 36 19 32 19 25 C 19 17 26 12 37 12 C 47 12 56 16 64 21 Z'
P='M 0 0 L 34 0 C 62 0 79 13 79 35 C 79 57 62 71 34 71 L 18 71 L 18 100 L 0 100 Z M 18 16 L 18 55 L 33 55 C 51 55 61 48 61 35 C 61 22 51 16 33 16 Z'
I='M 0 0 L 18 0 L 18 91 L 9 100 L 0 100 Z'
O='M 46 -2 C 18 -2 0 19 0 50 C 0 81 18 102 46 102 C 74 102 92 81 92 50 C 92 19 74 -2 46 -2 Z M 46 15 C 63 15 74 28 74 50 C 74 72 63 85 46 85 C 29 85 18 72 18 50 C 18 28 29 15 46 15 Z'
letters=[(S,0),(P,96),(P,194),(I,295),(O,337)]; WW=429
# All path contours drawn even-odd.
def svg(name,mode='primary',col=INK,accent=ACC):
    if mode=='symbol': w,h=140,140; body=f'<g transform="translate(20 20)">'; body+=''.join(f'<path d="{p}" fill="{accent}"/>' for p in icon);body+='</g>'
    else:
        stacked=mode=='stacked';w,h=(469,300) if stacked else (625,160)
        body=f'<g transform="translate({184 if stacked else 20} 20)">'+''.join(f'<path d="{p}" fill="{accent}"/>' for p in icon)+'</g>'
        body+=f'<g transform="translate({20 if stacked else 166} {166 if stacked else 38})">'+''.join(f'<path transform="translate({x} 0)" d="{p}" fill="{col}" fill-rule="evenodd"/>' for p,x in letters)+'</g>'
    s=f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" role="img" aria-label="SPPIO"><title>SPPIO — Open Aperture</title>{body}</svg>'
    (B/name).write_text(s);return s
for name,mode,c,a in [('sppio-primary.svg','primary',INK,ACC),('sppio-stacked.svg','stacked',INK,ACC),('sppio-symbol.svg','symbol',INK,ACC),('sppio-monochrome.svg','primary','#000000','#000000'),('sppio-reversed.svg','primary',WHITE,WHITE),('sppio-symbol-reversed.svg','symbol',WHITE,WHITE)]: svg(name,mode,c,a)
for p in B.glob('*.svg'):
    subprocess.run(['inkscape',str(p),'--export-type=png',f'--export-filename={p.with_suffix(".png")}','--export-width=3000'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True)
for n in [16,24,32,48,64,180,192,512]:
    im=Image.open(B/'sppio-symbol.png'); im.resize((n,n),Image.Resampling.LANCZOS).save(B/f'icon-{n}.png')
Image.open(B/'icon-48.png').save(B/'favicon.ico',sizes=[(16,16),(32,32),(48,48)])
# draw native PDF vectors from the same paths
C=canvas.Canvas(str(B/'SPPIO_Brand_Identity.pdf'),pagesize=(1200,750)); C.setTitle('SPPIO | Open Aperture — Identity Proposal')
def color(c): C.setFillColor(HexColor(c))
def rect(x,y,w,h,c,r=0):
    color(c); C.roundRect(x,750-y-h,w,h,r,stroke=0,fill=1) if r else C.rect(x,750-y-h,w,h,stroke=0,fill=1)
def txt(x,y,s,size=16,c=INK,font='Helvetica'):
    color(c);C.setFont(font,size);C.drawString(x,750-y-size*.8,s)
def text(x,y,s,width=540,size=17,c=MUT):
    import textwrap
    lines=textwrap.wrap(s,width=int(width/(size*.49)))
    for i,l in enumerate(lines):txt(x,y+i*size*1.5,l,size,c)
    return len(lines)*size*1.5

def path(d,x,y,sc,c):
    ts=re.findall('[MLCZ]|-?\\d+(?:\\.\\d+)?',d); p=C.beginPath();i=0
    def xy(a,b): return x+float(a)*sc,750-y-float(b)*sc
    while i<len(ts):
        op=ts[i];i+=1
        if op in ['M','L']:
            v=xy(ts[i],ts[i+1]);i+=2
            p.moveTo(*v) if op=='M' else p.lineTo(*v)
        elif op=='C':
            a=xy(ts[i],ts[i+1]);b=xy(ts[i+2],ts[i+3]);v=xy(ts[i+4],ts[i+5]);i+=6;p.curveTo(*a,*b,*v)
        else:p.close()
    color(c);C.drawPath(p,fill=1,stroke=0,fillMode=0)
def sym(x,y,s=1,c=ACC):
    for p in icon:path(p,x,y,s,c)
def word(x,y,s=1,c=INK):
    for p,dx in letters:path(p,x+dx*s,y,s,c)
def logo(x,y,w,c=INK,a=ACC):
    sc=w/575;sym(x,y,sc,a);word(x+146*sc,y+18*sc,sc,c)
def page(n,title,sub='',dark=False):
    rect(0,0,1200,750,INK if dark else PAPER);txt(48,27,'SPPIO / OPEN APERTURE',11,WHITE if dark else INK);txt(1075,27,f'2026   /   {n:02}',11,WHITE if dark else INK)
    if title:txt(48,85,title,38,WHITE if dark else INK)
    if sub:txt(49,139,sub,15,'#C3B7C6' if dark else MUT)
    txt(48,714,'DESIGN PROPOSAL  /  COMMERCIAL ADOPTION SUBJECT TO NAME & MARK CLEARANCE',9,'#C3B7C6' if dark else MUT)
def end(): C.showPage()
page(1,'','');txt(48,105,'GLOBAL ENTERPRISE IDENTITY',14,ACC);logo(115,255,970);txt(49,540,'Open systems. Considered design.',32);text(50,598,'A new identity built around an open aperture, expressive restraint and custom-drawn lettering.',750,20);end()
page(2,'A deliberate opening.','Concept and strategic rationale')
sym(70,230,2.8);text(470,220,'Two offset architectural elements form an open field. Opposing diagonal entries create a passage through a stable outer structure: controlled access without a literal shield, and connection without network-node imagery.',650,23)
text(470,440,'The silhouette is intentionally asymmetric. Its 18-unit bands, 45-degree entrances and unequal interior steps give the mark a repeatable construction logic. The meaning is a design rationale, not a claim that the symbol is universally unique.',650,18)
txt(470,595,'TRUST  /  OPENNESS  /  SYSTEMS AT SCALE',13,ACC);end()
page(3,'One master. Every configuration.','Primary horizontal, compact stacked, one-color and reverse')
logo(65,215,620);sym(900,205,1.35);word(755,378,.72)
rect(48,480,530,170,WHITE);logo(78,520,450,'#000000','#000000');rect(605,480,547,170,INK);logo(640,520,450,WHITE,WHITE);end()
page(4,'Lettering with a human rhythm.','Custom vector outlines / no font dependency in the logo')
word(70,245,2.4);text(55,580,'S: modulated curves and open terminals. P/P: shared bowls preserve the name rhythm. I: a restrained diagonal foot echoes the aperture. O: an oval counter softens the engineered geometry.',1080,19)
txt(55,655,'The wordmark is a fixed drawing, not an installable alphabet or a commercially cleared typeface.',13,ACC);end()
page(5,'A warmer technology palette.','Aubergine anchors the system; copper identifies the aperture.')
for x,c,name,code in [(50,INK,'AUBERGINE',INK),(420,ACC,'COPPER',ACC),(790,PAPER,'PORCELAIN',PAPER)]:
    rect(x,210,340,260,c);txt(x,500,name,14);txt(x,535,code,28);txt(x,582,{'#302337':'RGB 48 / 35 / 55','#B54F34':'RGB 181 / 79 / 52','#F6F2ED':'RGB 246 / 242 / 237'}[code],16)
text(50,640,'Use aubergine for text and copper for identity accents. Supporting type: system sans-serif for interfaces; Arial for editable office files. Neither is the logo lettering. CMYK and spot matches require printer proofing.',1090,16);end()
page(6,'Built into the interface.','Website navigation and enterprise console / light and dark concepts')
for x,bg,fg in [(48,WHITE,INK),(625,INK,WHITE)]:
    rect(x,195,527,455,bg,12);logo(x+24,219,148,fg,ACC if fg==INK else WHITE);txt(x+300,230,'Platform   /   Sign in',12,fg)
    txt(x+25,315,'Operate with clarity.',29,fg);text(x+25,365,'Infrastructure, intelligence and control in one workspace.',450,16,fg)
    for k,v in enumerate(['Services   24','Regions   06','Status   Healthy']):rect(x+25+k*159,445,146,87,PAPER if fg==INK else '#48394F',6);txt(x+35+k*159,470,v,13,fg)
    rect(x+25,565,165,43,ACC,5);txt(x+43,580,'Open workspace',14,WHITE)
end()
page(7,'Recognizable in a small space.','Application icon, favicon ladder and operating-system startup')
rect(65,225,210,210,INK,42);sym(110,270,1.2,WHITE)
for k,n in enumerate([16,24,32,48,64]):
    x=350+k*112;C.drawImage(str(B/f'icon-{n}.png'),x,750-310-n,width=n,height=n,mask='auto');txt(x,400,f'{n}px',14)
rect(350,475,780,170,INK,12);logo(600,510,280,WHITE,WHITE);txt(630,610,'Starting your workspace',13,WHITE)
text(65,500,'Use only the symbol below 120px lockup width. The 16px icon is a raster export of the same paths; keep both entrances visible.',245,16)
end()
page(8,'Consistent in the real world.','Business card, official correspondence and employee identification')
rect(50,220,430,235,INK,4);logo(78,250,230,WHITE,WHITE);txt(80,365,'Avery Rao',21,WHITE);txt(80,400,'Engineering / example identity',13,WHITE)
rect(525,205,340,440,WHITE);logo(550,230,170);txt(550,325,'OFFICIAL CORRESPONDENCE',12,ACC);txt(550,366,'A clear point of view.',22)
for k in range(7):rect(550,425+k*17,265 if k%3 else 220,3,LINE)
rect(910,240,235,350,WHITE,10);rect(992,220,70,12,ACC,6);logo(929,266,190);rect(965,340,125,100,PAPER);txt(985,380,'PHOTO',13,MUT);txt(932,477,'Avery Rao',20);txt(932,510,'ENGINEERING',11,ACC);txt(932,548,'EXAMPLE / 00001',10)
end()
page(9,'A visible corporate presence.','Architectural elevation study / exact vector artwork')
rect(48,205,1104,450,'#D8D3CD');
for x in range(70,1150,130):rect(x,205,2,450,'#BBB6B2')
rect(48,580,1104,75,'#C5C0BB');logo(270,315,680);txt(75,610,'SPPIO / CAMPUS',12,INK)
text(50,665,'Signage uses the original silhouette; fabricator to determine fixings, material tolerances and illumination.',1080,15);end()
page(10,'One family. Clear product roles.','Software, developer platform and presentation templates')
for i,name in enumerate(['Cloud','Security','AI','Developers']):
    x=55+(i%2)*560;y=205+(i//2)*135;logo(x,y,220);txt(x+250,y+20,name,25)
rect(55,515,510,145,INK);logo(78,538,150,WHITE,WHITE);txt(80,601,'Engineering at scale',26,WHITE)
rect(605,515,540,145,WHITE);txt(630,535,'01 / SYSTEM OVERVIEW',12,ACC);txt(630,580,'A repeatable presentation grid.',24);txt(630,625,'48px margins / one message / clear hierarchy',13,MUT);end()
page(11,'Rules that protect recognition.','Clear space, minimum sizes and background use')
sym(95,240,2);C.setStrokeColor(HexColor(ACC));C.setDash(4,4);C.rect(59,750-476,272,272,stroke=1,fill=0);C.setDash();txt(60,510,'x = 18 / minimum clear space = x',15)
text(420,220,'Clear space: one 18-unit band outside the visible artwork bounds. Keep the 46-unit symbol-to-wordmark gap. Never retype the name, rotate components, stretch the lockup or add effects to master artwork.',700,20)
text(420,395,'Minimum guidance: horizontal lockup 120px / 28mm; standalone symbol 16px / 5mm. Prefer 24px for dense interfaces and 180px for primary navigation. These are initial production recommendations, not user-study findings.',700,18)
text(420,555,'Use the two-color master on porcelain or white. Use all-white on aubergine and all-black on plain light stock. Copper is an accent, not small body copy. Avoid photographs unless a solid holding panel is supplied.',700,18);end()
page(12,'Distinctiveness review: adoption on hold.','Preliminary screening / 28 October 2026 / not legal clearance')
text(50,205,'VERIFIED: An SEC-hosted 2006 software licence agreement names an Airbee application SPPIO. This exact-name historical use in related technology is a material issue for counsel to investigate. Current rights, ownership, territories and continuing use were not established.',1090,21,INK)
text(50,355,'ALSO FOUND: SPIO is currently presented at spio.app as an offline AI speech application. The spelling variant deserves phonetic and commercial-impression review. The search also found SPPIO used by an unrelated French landscape association.',1090,18)
text(50,475,'NOT COMPLETED: Live exact/phonetic searches within IP India, WIPO, USPTO and EUIPO; image-similarity and design-code searches; unregistered-market investigation; ownership and status verification. WIPO presented a challenge page; IP India could not be retrieved. No registry no-match conclusion is made.',1090,18)
text(50,605,'DESIGN CHECK: No stock symbol, external vector or font outline was used in the master. Generic broken-frame/aperture geometry remains a similarity risk. Search the symbol separately. Changing artwork cannot resolve a conflicting name.',1090,17,ACC);end()
page(13,'Review record and next decisions.','Evidence, scope and handoff')
items=[('1 / Exact historical technology use','SEC Exhibit 10.13, Software License Agreement No. 2006-03, Exhibit A.\nhttps://www.sec.gov/Archives/edgar/data/1297533/000114420406040880/v054054_ex10-13.htm'),('2 / Similar-name market use','SPIO speech application: https://spio.app/\nUnrelated exact acronym: https://sppio-oleron.fr/'),('3 / Official search resources','https://www.wipo.int/en/web/global-brand-database/index\nhttps://tmrsearch.ipindia.gov.in/tmrpublicsearch/\nhttps://www.uspto.gov/trademarks/search/federal-trademark-searching\nhttps://www.euipo.europa.eu/search-ip')]
y=200
for t,s in items:
 txt(50,y,t,18,INK);y+=32
 for l in s.split('\n'):txt(50,y,l,12,MUT);y+=21
 y+=24
text(50,610,'Counsel brief: India first, then US/EU and intended markets. Start with software and SaaS goods/services (often Classes 9 and 42), widening to related offerings. Search SPPIO, SPIO, SP PIO, SP-PIO, S P P I O and pronunciation variants. Do not limit review to class numbers.',1090,17)
end();C.save()
# Explicit deliverable notes, not a claim of legal ownership.
(B/'README.txt').write_text('SPPIO / OPEN APERTURE — DESIGN PROPOSAL\n\nCommercial adoption on hold pending professional name and mark clearance. Exact historical technology use of SPPIO was found in an SEC-hosted agreement. See PDF pages 12–13.\n\nFiles: editable path-only SVG masters; 3000px-wide transparent PNG exports; 16–512px icon PNGs; favicon ICO; PDF identity presentation. All masters derive from build_identity.py geometry.\n\nThe wordmark is custom-drawn for the five letters SPPIO, not an installable font. Supporting typography is system sans-serif / Arial.\n\nSVGs use solid fills and even-odd counters. PNGs are RGB with alpha. Printer must create and proof CMYK/spot conversions. Mockups and applications are illustrative, not implemented products. Minimum size recommendations need field validation. No registry clearance, image-similarity search, or guarantee of exclusive rights is provided.\n')
# Native proof preview
subprocess.run(['pdftoppm','-f','1','-singlefile','-scale-to','1600','-png',str(B/'SPPIO_Brand_Identity.pdf'),str(B/'cover')],check=True,stdout=subprocess.DEVNULL)
print(str(B))
