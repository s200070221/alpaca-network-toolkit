// 交換器常用機種埠定義 DEVICE_MODELS（人工整理；XN191 由 switch-generator-app.js 搬出，產生器與交換器分析頁共用）
// 頂層 const：classic script 共用全域詞法作用域，產生器的 validate.js／app.js 與交換器分析的前面板示意直接引用
// 常用機種預設 Interface 清單：純前端 UI 便利功能，不涉及 switch_analyzer、不影響
// round-trip 正確性。ports 陣列每項目要嘛是 {prefix,from,to,speed}（連續編號的一般
// 埠位，展開成 prefix+N）要嘛是 {name,speed,mgmt:true}（單一命名的 mgmt 介面）
const DEVICE_MODELS={
  comware:[
    {value:'hpe5130-24',label:'HPE 5130 24G 4SFP+ EI (JG932A)',ports:[{prefix:'GigabitEthernet1/0/',from:1,to:24,speed:'1G'},{prefix:'Ten-GigabitEthernet1/0/',from:25,to:28,speed:'10G'},{name:'M-GigabitEthernet0/0/0',speed:'1G',mgmt:true}],poe:false},
    {value:'hpe5130-48',label:'HPE 5130 48G 4SFP+ EI (JG934A)',ports:[{prefix:'GigabitEthernet1/0/',from:1,to:48,speed:'1G'},{prefix:'Ten-GigabitEthernet1/0/',from:49,to:52,speed:'10G'},{name:'M-GigabitEthernet0/0/0',speed:'1G',mgmt:true}],poe:false},
    
    {value:'hpe12900',label:'HPE 12900 (模組化機箱；以插槽 1 的 100G 線卡示意，依實際線卡調整)',ports:[{prefix:'HundredGigE1/0/',from:1,to:4,speed:'100G'},{name:'M-GigabitEthernet0/0/0',speed:'1G',mgmt:true}],poe:false},
    {value:'hpe5140-24',label:'HPE 5140 24G 2SFP+ 2XGT EI (R8J41A，2×SFP+ 與 2×10GBASE-T 共 4 個 10G 上行)',ports:[{prefix:'GigabitEthernet1/0/',from:1,to:24,speed:'1G'},{prefix:'Ten-GigabitEthernet1/0/',from:25,to:28,speed:'10G'},{name:'M-GigabitEthernet0/0/0',speed:'1G',mgmt:true}],poe:false},
    {value:'hpe5140-48',label:'HPE 5140-48G-4SFP+',ports:[
      {prefix:'GigabitEthernet1/0/',from:1,to:48,speed:'1G'},
      {prefix:'Ten-GigabitEthernet1/0/',from:49,to:52,speed:'10G'},
      {name:'M-GigabitEthernet0/0/0',speed:'1G',mgmt:true}],poe:false},
    {value:'hpe5710-48',label:'HPE FlexFabric 5710 48SFP+ 6QSFP+ or 2QSFP28 (JL585A；原「5710 48G 4SFP+」非實際型號)',ports:[{prefix:'Ten-GigabitEthernet1/0/',from:1,to:48,speed:'10G'},{prefix:'FortyGigE1/0/',from:49,to:54,speed:'40G'},{name:'M-GigabitEthernet0/0/0',speed:'1G',mgmt:true}],poe:false},
    {value:'hpe5945',label:'HPE FlexFabric 5945 (模組化；埠依所裝模組，以 2×100G 示意)',ports:[
      {prefix:'HundredGigE1/0/',from:1,to:2,speed:'100G'},
      {name:'M-GigabitEthernet0/0/0',speed:'1G',mgmt:true}],poe:false},
    {value:'hpe5945-2slot',label:'HPE FlexFabric 5945 2-slot (模組槽；埠依所裝模組，以 2×100G 示意)',ports:[
      {prefix:'HundredGigE1/0/',from:1,to:2,speed:'100G'},
      {name:'M-GigabitEthernet0/0/0',speed:'1G',mgmt:true}],poe:false},
    {value:'hpe5945-4slot',label:'HPE FlexFabric 5945 4-slot (模組槽；埠依所裝模組，以 8×100G 示意)',ports:[
      {prefix:'HundredGigE1/0/',from:1,to:8,speed:'100G'},
      {name:'M-GigabitEthernet0/0/0',speed:'1G',mgmt:true}],poe:false},
    {value:'hpe5945-48sfp28-8qsfp28',label:'HPE FlexFabric 5945 48SFP28 8QSFP28',ports:[
      {prefix:'Twenty-FiveGigE1/0/',from:1,to:48,speed:'25G'},
      {prefix:'HundredGigE1/0/',from:49,to:56,speed:'100G'},
      {name:'M-GigabitEthernet0/0/0',speed:'1G',mgmt:true}],poe:false},
    {value:'hpe5720-32',label:'HPE 5720 32×SFP+ 1G/10G + 6×QSFP28 100G (S2N57A)',ports:[
      {prefix:'Ten-GigabitEthernet1/0/',from:1,to:32,speed:'10G'},
      {prefix:'HundredGigE1/0/',from:33,to:38,speed:'100G'},
      {name:'M-GigabitEthernet0/0/0',speed:'1G',mgmt:true}],poe:false},
    {value:'hpe5720-48',label:'HPE 5720 48×SFP+ 1G/10G + 6×QSFP28 100G (S2N58A)',ports:[
      {prefix:'Ten-GigabitEthernet1/0/',from:1,to:48,speed:'10G'},
      {prefix:'HundredGigE1/0/',from:49,to:54,speed:'100G'},
      {name:'M-GigabitEthernet0/0/0',speed:'1G',mgmt:true}],poe:false},
    {value:'hpe5720-24t',label:'HPE 5720 24×10GBASE-T + 8×SFP+ 1G/10G + 6×QSFP28 100G (S2N59A)',ports:[
      {prefix:'Ten-GigabitEthernet1/0/',from:1,to:32,speed:'10G'},
      {prefix:'HundredGigE1/0/',from:33,to:38,speed:'100G'},
      {name:'M-GigabitEthernet0/0/0',speed:'1G',mgmt:true}],poe:false},
    {value:'hpe5720-40t',label:'HPE 5720 40×10GBASE-T + 8×SFP+ 1G/10G + 6×QSFP28 100G (S2N60A)',ports:[
      {prefix:'Ten-GigabitEthernet1/0/',from:1,to:48,speed:'10G'},
      {prefix:'HundredGigE1/0/',from:49,to:54,speed:'100G'},
      {name:'M-GigabitEthernet0/0/0',speed:'1G',mgmt:true}],poe:false},
    {value:'hpe5510-24',label:'HPE FlexNetwork 5510 24G 4SFP+ HI (JH145A)',ports:[
      {prefix:'GigabitEthernet1/0/',from:1,to:24,speed:'1G'},
      {prefix:'Ten-GigabitEthernet1/0/',from:25,to:28,speed:'10G'},
      {name:'M-GigabitEthernet0/0/0',speed:'1G',mgmt:true}],poe:false},
    {value:'hpe5510-48',label:'HPE FlexNetwork 5510 48G 4SFP+ HI (JH146A)',ports:[
      {prefix:'GigabitEthernet1/0/',from:1,to:48,speed:'1G'},
      {prefix:'Ten-GigabitEthernet1/0/',from:49,to:52,speed:'10G'},
      {name:'M-GigabitEthernet0/0/0',speed:'1G',mgmt:true}],poe:false},
    {value:'hpe5510-24poe',label:'HPE FlexNetwork 5510 24G PoE+ 4SFP+ HI (JH147A)',ports:[
      {prefix:'GigabitEthernet1/0/',from:1,to:24,speed:'1G'},
      {prefix:'Ten-GigabitEthernet1/0/',from:25,to:28,speed:'10G'},
      {name:'M-GigabitEthernet0/0/0',speed:'1G',mgmt:true}],poe:true,poeRange:[1,24]},
  ],
  cisco:[
    {value:'c9300-24',label:'Catalyst 9300-24T (含選購 C9300-NM-4X 上行模組 Te1/1/1-4)',ports:[{prefix:'GigabitEthernet1/0/',from:1,to:24,speed:'1G'},{prefix:'TenGigabitEthernet1/1/',from:1,to:4,speed:'10G'},{name:'GigabitEthernet0/0',speed:'1G',mgmt:true}],poe:false},
    {value:'c2960-48',label:'Catalyst 2960X-48TD-L (48×1G + 2×10G SFP+)',ports:[{prefix:'GigabitEthernet1/0/',from:1,to:48,speed:'1G'},{prefix:'TenGigabitEthernet1/0/',from:1,to:2,speed:'10G'},{name:'GigabitEthernet0/0',speed:'1G',mgmt:true}],poe:false},
    {value:'c3650-24',label:'Catalyst 3650-24PD (24×1G PoE+ + 2×1G SFP + 2×10G SFP+)',ports:[{prefix:'GigabitEthernet1/0/',from:1,to:24,speed:'1G'},{prefix:'GigabitEthernet1/1/',from:1,to:2,speed:'1G'},{prefix:'TenGigabitEthernet1/1/',from:3,to:4,speed:'10G'},{name:'GigabitEthernet0/0',speed:'1G',mgmt:true}],poe:true,poeRange:[1,24]},
    {value:'c9500-40',label:'Catalyst 9500-40X (40×10G)',ports:[{prefix:'TenGigabitEthernet1/0/',from:1,to:40,speed:'10G'},{name:'GigabitEthernet0/0',speed:'1G',mgmt:true}],poe:false},
    {value:'c9600-48',label:'Catalyst 9600 (模組化；以插槽 1 的 C9600-LC-48YL 線卡示意，48×25G SFP28)',ports:[{prefix:'TwentyFiveGigE1/0/',from:1,to:48,speed:'25G'},{name:'GigabitEthernet0/0',speed:'1G',mgmt:true}],poe:false},
    {value:'c9300-48',label:'Catalyst 9300-48P (48×1G PoE+，含選購 C9300-NM-4X 上行模組 Te1/1/1-4)',ports:[{prefix:'GigabitEthernet1/0/',from:1,to:48,speed:'1G'},{prefix:'TenGigabitEthernet1/1/',from:1,to:4,speed:'10G'},{name:'GigabitEthernet0/0',speed:'1G',mgmt:true}],poe:true,poeRange:[1,48]},
    {value:'c9300x-48hx',label:'Catalyst 9300X-48HX (48×mGig 10G UPOE+；上行為選購 C9300X-NM 模組，未列)',ports:[{prefix:'TenGigabitEthernet1/0/',from:1,to:48,speed:'10G'},{name:'GigabitEthernet0/0',speed:'1G',mgmt:true}],poe:true,poeRange:[1,48]},
    {value:'c9500-24y4c',label:'Catalyst 9500-24Y4C (光纖骨幹，不支援 Breakout)',ports:[{prefix:'TwentyFiveGigE1/0/',from:1,to:24,speed:'25G'},{prefix:'HundredGigE1/0/',from:25,to:28,speed:'100G'},{name:'GigabitEthernet0/0',speed:'1G',mgmt:true}],poe:false},
    {value:'c9500-32c',label:'Catalyst 9500-32C (支援 Breakout：100G→4x25G)',ports:[
      {prefix:'HundredGigE1/0/',from:1,to:32,speed:'100G'},
      {name:'GigabitEthernet0/0',speed:'1G',mgmt:true}],poe:false},
    {value:'c9200l-24p-4x',label:'Catalyst 9200L-24P-4X (存取層 PoE+)',ports:[
      {prefix:'GigabitEthernet1/0/',from:1,to:24,speed:'1G'},
      {prefix:'TenGigabitEthernet1/1/',from:1,to:4,speed:'10G'},
      {name:'GigabitEthernet0/0',speed:'1G',mgmt:true}],poe:true,poeRange:[1,24]},
    {value:'c9200l-48p-4x',label:'Catalyst 9200L-48P-4X (存取層 PoE+)',ports:[
      {prefix:'GigabitEthernet1/0/',from:1,to:48,speed:'1G'},
      {prefix:'TenGigabitEthernet1/1/',from:1,to:4,speed:'10G'},
      {name:'GigabitEthernet0/0',speed:'1G',mgmt:true}],poe:true,poeRange:[1,48]},
    {value:'c9400-lc-48ux',label:'Catalyst 9400 (模組化；以插槽 1 的 C9400-LC-48UX 線卡示意：埠 1-24 為 1G UPOE、25-48 為 mGig 10G UPOE)',ports:[{prefix:'GigabitEthernet1/0/',from:1,to:24,speed:'1G'},{prefix:'TenGigabitEthernet1/0/',from:25,to:48,speed:'10G'},{name:'GigabitEthernet0/0',speed:'1G',mgmt:true}],poe:true,poeRange:[1,48]},
    {value:'c9350-24',label:'Catalyst 9350-24P (24×1G PoE+；上行為選購模組，未列)',ports:[{prefix:'GigabitEthernet1/0/',from:1,to:24,speed:'1G'},{name:'GigabitEthernet0/0',speed:'1G',mgmt:true}],poe:true,poeRange:[1,24]},
    {value:'c9350-48',label:'Catalyst 9350-48HX (48×mGig 10G UPOE+；上行為選購模組，未列)',ports:[{prefix:'TenGigabitEthernet1/0/',from:1,to:48,speed:'10G'},{name:'GigabitEthernet0/0',speed:'1G',mgmt:true}],poe:true,poeRange:[1,48]},
    {value:'c9200cx-12p',label:'Catalyst 9200CX-12P-2X2G (12×1G PoE+ + 2×1G SFP + 2×10G SFP+)',ports:[{prefix:'GigabitEthernet1/0/',from:1,to:12,speed:'1G'},{prefix:'GigabitEthernet1/1/',from:1,to:2,speed:'1G'},{prefix:'TenGigabitEthernet1/1/',from:3,to:4,speed:'10G'},{name:'GigabitEthernet0/0',speed:'1G',mgmt:true}],poe:true,poeRange:[1,12]},
  ],
  aruba:[
    {value:'aruba6300m-24',label:'Aruba CX 6300M-24G-4SFP56',ports:[{prefix:'1/1/',from:1,to:24,speed:'1G'},{prefix:'1/1/',from:25,to:28,speed:'50G'},{name:'mgmt',speed:'1G',mgmt:true}],poe:false},
    {value:'aruba6300-48',label:'Aruba CX 6300M-48G-4SFP56',ports:[{prefix:'1/1/',from:1,to:48,speed:'1G'},{prefix:'1/1/',from:49,to:52,speed:'50G'},{name:'mgmt',speed:'1G',mgmt:true}],poe:false},
    {value:'aruba6200f-48',label:'Aruba CX 6200F-48G-4SFP+',ports:[{prefix:'1/1/',from:1,to:48,speed:'1G'},{prefix:'1/1/',from:49,to:52,speed:'10G'},{name:'mgmt',speed:'1G',mgmt:true}],poe:false},
    {value:'aruba8300',label:'Aruba CX 8320-48XF6Q (48×10G SFP+ + 6×40G QSFP+；原「8300 模組化」非實際型號)',ports:[{prefix:'1/1/',from:1,to:48,speed:'10G'},{prefix:'1/1/',from:49,to:54,speed:'40G'},{name:'mgmt',speed:'1G',mgmt:true}],poe:false},
    {value:'aruba8325',label:'Aruba CX 8325-48Y8C (48×25G + 8×100G)',ports:[{prefix:'1/1/',from:1,to:48,speed:'25G'},{prefix:'1/1/',from:49,to:56,speed:'100G'},{name:'mgmt',speed:'1G',mgmt:true}],poe:false},
    {value:'aruba6200f-24',label:'Aruba CX 6200F-24G-4SFP+',ports:[{prefix:'1/1/',from:1,to:24,speed:'1G'},{prefix:'1/1/',from:25,to:28,speed:'10G'},{name:'mgmt',speed:'1G',mgmt:true}],poe:false},
    {value:'aruba6300f-48',label:'Aruba CX 6300F-48G-PoE4-4SFP56 (PoE Class 4)',ports:[{prefix:'1/1/',from:1,to:48,speed:'1G'},{prefix:'1/1/',from:49,to:52,speed:'50G'},{name:'mgmt',speed:'1G',mgmt:true}],poe:true,poeRange:[1,48]},
    {value:'aruba8360-24xf',label:'Aruba CX 8360-24XF2C (24×10G + 2×100G)',ports:[{prefix:'1/1/',from:1,to:24,speed:'10G'},{prefix:'1/1/',from:25,to:26,speed:'100G'},{name:'mgmt',speed:'1G',mgmt:true}],poe:false},
    {value:'aruba9300-32d',label:'Aruba CX 9300-32D (32×400G QSFP-DD，以 100G 表示 + 2×10G SFP+)',ports:[
      {prefix:'1/1/',from:1,to:32,speed:'100G'},
      {prefix:'1/1/',from:33,to:34,speed:'10G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:false},
    {value:'aruba6100-24',label:'Aruba CX 6100-24G-4SFP+',ports:[{prefix:'1/1/',from:1,to:24,speed:'1G'},{prefix:'1/1/',from:25,to:28,speed:'10G'},{name:'mgmt',speed:'1G',mgmt:true}],poe:false},
    {value:'aruba6100-48p',label:'Aruba CX 6100-48G-PoE4-4SFP+ (48×802.3at PoE+ 370W)',ports:[{prefix:'1/1/',from:1,to:48,speed:'1G'},{prefix:'1/1/',from:49,to:52,speed:'10G'},{name:'mgmt',speed:'1G',mgmt:true}],poe:true,poeRange:[1,48]},
  ],
  fortiswitch:[
    {value:'fs-124f',label:'FortiSwitch 124F',ports:[
      {prefix:'port',from:1,to:24,speed:'1G'},
      {prefix:'port',from:25,to:28,speed:'10G'},
      {name:'mgmt',speed:'1G',mgmt:true},
    ],poe:false},
    // XN169：原「FortiSwitch 224F (2xM.2+24xG)」查無此型號（Fortinet 只有 224D／224E），改為 FS-224E（24×GE RJ45＋4×GE SFP，NetBox 同）
    {value:'fs-224e',label:'FortiSwitch 224E (24×1G + 4×1G SFP)',ports:[{prefix:'port',from:1,to:28,speed:'1G'},{name:'mgmt',speed:'1G',mgmt:true}],poe:false},
    {value:'fs-1048e',label:'FortiSwitch 1048E (48×1/10G SFP+ + 4×100G + 2×40G)',ports:[{prefix:'port',from:1,to:48,speed:'1G'},{prefix:'port',from:49,to:52,speed:'100G'},{prefix:'port',from:53,to:54,speed:'40G'},{name:'mgmt',speed:'1G',mgmt:true}],poe:false},
    {value:'fs-3032g',label:'FortiSwitch 3032G (32×100G + 2×10G)',ports:[{prefix:'port',from:1,to:32,speed:'100G'},{prefix:'port',from:33,to:34,speed:'10G'},{name:'mgmt',speed:'1G',mgmt:true}],poe:false},
    {value:'fs-124f-poe',label:'FortiSwitch 124F-POE (24x802.3af 95W)',ports:[
      {prefix:'port',from:1,to:24,speed:'1G'},
      {prefix:'port',from:25,to:28,speed:'10G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:true,poeRange:[1,24]},
    {value:'fs-124f-fpoe',label:'FortiSwitch 124F-FPOE (24x802.3at 180W)',ports:[
      {prefix:'port',from:1,to:24,speed:'1G'},
      {prefix:'port',from:25,to:28,speed:'10G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:true,poeRange:[1,24]},
    {value:'fs-148f',label:'FortiSwitch 148F',ports:[
      {prefix:'port',from:1,to:48,speed:'1G'},
      {prefix:'port',from:49,to:52,speed:'10G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:false},
    {value:'fs-148f-poe',label:'FortiSwitch 148F-POE (48x802.3af 370W)',ports:[
      {prefix:'port',from:1,to:48,speed:'1G'},
      {prefix:'port',from:49,to:52,speed:'10G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:true,poeRange:[1,48]},
    {value:'fs-148f-fpoe',label:'FortiSwitch 148F-FPOE (48x802.3at 740W)',ports:[
      {prefix:'port',from:1,to:48,speed:'1G'},
      {prefix:'port',from:49,to:52,speed:'10G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:true,poeRange:[1,48]},
    {value:'fs-424d',label:'FortiSwitch 424D',ports:[
      {prefix:'port',from:1,to:24,speed:'1G'},
      {prefix:'port',from:25,to:26,speed:'10G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:false},
    {value:'fs-424d-poe',label:'FortiSwitch 424D-POE (24x802.3af 180W)',ports:[
      {prefix:'port',from:1,to:24,speed:'1G'},
      {prefix:'port',from:25,to:26,speed:'10G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:true,poeRange:[1,24]},
    {value:'fs-424d-fpoe',label:'FortiSwitch 424D-FPOE (24x802.3at 370W)',ports:[
      {prefix:'port',from:1,to:24,speed:'1G'},
      {prefix:'port',from:25,to:26,speed:'10G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:true,poeRange:[1,24]},
    {value:'fs-1024d',label:'FortiSwitch 1024D (24×1/10G SFP)',ports:[
      {prefix:'port',from:1,to:24,speed:'10G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:false},
    {value:'fs-1024e',label:'FortiSwitch 1024E (24×1/10G SFP + 2×100G)',ports:[
      {prefix:'port',from:1,to:24,speed:'10G'},
      {prefix:'port',from:25,to:26,speed:'100G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:false},
    {value:'fs-t1024e',label:'FortiSwitch T1024E (24×10G RJ45 + 2×100G)',ports:[
      {prefix:'port',from:1,to:24,speed:'10G'},
      {prefix:'port',from:25,to:26,speed:'100G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:false},
    {value:'fs-124g',label:'FortiSwitch 124G (24×2.5G + 6×10G SFP+)',ports:[{prefix:'port',from:1,to:24,speed:'2.5G'},{prefix:'port',from:25,to:30,speed:'10G'},{name:'mgmt',speed:'1G',mgmt:true}],poe:false},
    {value:'fs-424e',label:'FortiSwitch 424E (24xGE+4x10G，正確型號應為 424E 非現有的 424D)',ports:[
      {prefix:'port',from:1,to:24,speed:'1G'},
      {prefix:'port',from:25,to:28,speed:'10G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:false},
    {value:'fs-624f',label:'FortiSwitch 624F (24×1/2.5/5G Multi-Gig RJ45 + 4×25G SFP28 Uplink，MACsec)',ports:[
      {prefix:'port',from:1,to:24,speed:'5G'},
      {prefix:'port',from:25,to:28,speed:'25G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:false},
    {value:'fs-624f-fpoe',label:'FortiSwitch 624F-FPOE (24×802.3bt Multi-Gig PoE + 4×25G SFP28 Uplink)',ports:[
      {prefix:'port',from:1,to:24,speed:'5G'},
      {prefix:'port',from:25,to:28,speed:'25G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:true,poeRange:[1,24]},
    {value:'fs-648f',label:'FortiSwitch 648F (32×2.5G + 16×5G Multi-Gig RJ45 + 8×25G SFP28)',ports:[{prefix:'port',from:1,to:32,speed:'2.5G'},{prefix:'port',from:33,to:48,speed:'5G'},{prefix:'port',from:49,to:56,speed:'25G'},{name:'mgmt',speed:'1G',mgmt:true}],poe:false},
    {value:'fs-648f-fpoe',label:'FortiSwitch 648F-FPOE (48×Multi-Gig 802.3bt PoE + 8×25G SFP28)',ports:[{prefix:'port',from:1,to:32,speed:'2.5G'},{prefix:'port',from:33,to:48,speed:'5G'},{prefix:'port',from:49,to:56,speed:'25G'},{name:'mgmt',speed:'1G',mgmt:true}],poe:true,poeRange:[1,48]},
    {value:'fs-108f',label:'FortiSwitch 108F (桌上型 入門，8×1G RJ45 + 2×1G SFP)',ports:[
      {prefix:'port',from:1,to:8,speed:'1G'},
      {prefix:'port',from:9,to:10,speed:'1G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:false},
    {value:'fs-108f-poe',label:'FortiSwitch 108F-POE (8×802.3at PoE+ 130W RJ45 + 2×1G SFP)',ports:[
      {prefix:'port',from:1,to:8,speed:'1G'},
      {prefix:'port',from:9,to:10,speed:'1G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:true,poeRange:[1,8]},
    {value:'fs-108f-fpoe',label:'FortiSwitch 108F-FPOE (8×802.3at PoE+ RJ45 + 2×1G SFP)',ports:[
      {prefix:'port',from:1,to:8,speed:'1G'},
      {prefix:'port',from:9,to:10,speed:'1G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:true,poeRange:[1,8]},
  ],
  juniper:[
    {value:'ex2300-24',label:'Juniper EX2300-24T',ports:[
      {prefix:'ge-0/0/',from:0,to:23,speed:'1G'},
      {prefix:'xe-0/1/',from:0,to:3,speed:'10G'},
      {name:'me0',speed:'1G',mgmt:true},
    ],poe:false},
    {value:'ex2200-24t',label:'Juniper EX2200-24T-4G (24×1G + 4×1G SFP)',ports:[{prefix:'ge-0/0/',from:0,to:23,speed:'1G'},{prefix:'ge-0/1/',from:0,to:3,speed:'1G'},{name:'me0',speed:'1G',mgmt:true}],poe:false},
    {value:'ex4100-24p',label:'Juniper EX4100-24P (24×1G PoE+ + 4×25G + 4×10G SFP+)',ports:[{prefix:'ge-0/0/',from:0,to:23,speed:'1G'},{prefix:'et-0/1/',from:0,to:3,speed:'25G'},{prefix:'xe-0/2/',from:0,to:3,speed:'10G'},{name:'me0',speed:'1G',mgmt:true}],poe:true,poeRange:[0,23]},
    {value:'qfx10002',label:'Juniper QFX10002-36Q (36×40G)',ports:[{prefix:'et-0/0/',from:0,to:35,speed:'40G'},{name:'me0',speed:'1G',mgmt:true}],poe:false},
    {value:'ex4400-48f',label:'Juniper EX4400-48F (36×1G SFP + 12×10G SFP+ + 2×100G)',ports:[{prefix:'ge-0/0/',from:0,to:35,speed:'1G'},{prefix:'xe-0/0/',from:36,to:47,speed:'10G'},{prefix:'et-0/1/',from:0,to:1,speed:'100G'},{name:'me0',speed:'1G',mgmt:true}],poe:false},
    {value:'qfx5120-48y',label:'Juniper QFX5120-48Y (48×25G + 8×100G)',ports:[{prefix:'et-0/0/',from:0,to:47,speed:'25G'},{prefix:'et-0/0/',from:48,to:55,speed:'100G'},{name:'me0',speed:'1G',mgmt:true}],poe:false},
    {value:'ex3400-24p',label:'Juniper EX3400-24P (24×1G PoE+ + 2×40G QSFP+ + 4×10G SFP+)',ports:[
      {prefix:'ge-0/0/',from:0,to:23,speed:'1G'},
      {prefix:'et-0/1/',from:0,to:1,speed:'40G'},
      {prefix:'xe-0/2/',from:0,to:3,speed:'10G'},
      {name:'me0',speed:'1G',mgmt:true}],poe:true,poeRange:[0,23]},
    {value:'ex4300-48p',label:'Juniper EX4300-48P (接入PoE，高密度)',ports:[
      {prefix:'ge-0/0/',from:0,to:47,speed:'1G'},
      {prefix:'et-0/1/',from:0,to:3,speed:'40G'},
      {name:'me0',speed:'1G',mgmt:true}],poe:true,poeRange:[0,47]},
    {value:'qfx5100-48s',label:'Juniper QFX5100-48S-6Q (48×10G + 6×40G)',ports:[{prefix:'xe-0/0/',from:0,to:47,speed:'10G'},{prefix:'et-0/0/',from:48,to:53,speed:'40G'},{name:'me0',speed:'1G',mgmt:true}],poe:false},
    {value:'ex4000-48mp',label:'Juniper EX4000-48MP (Wi-Fi 7 UPOE++，EX2300 後繼機，40×1G+8×2.5G PoE++ + 2×1/10G SFP+ Uplink)',ports:[{prefix:'mge-0/0/',from:0,to:7,speed:'2.5G'},{prefix:'ge-0/0/',from:8,to:47,speed:'1G'},{prefix:'xe-0/1/',from:0,to:3,speed:'10G'},{name:'me0',speed:'1G',mgmt:true}],poe:true,poeRange:[0,47]},
  ],
  cisco_nxos:[
    {value:'n3k-c3064pq-10ge',label:'Nexus 3064-PQ (48×10G SFP+ + 4×40G QSFP+)',ports:[{prefix:'Ethernet1/',from:1,to:48,speed:'10G'},{prefix:'Ethernet1/',from:49,to:52,speed:'40G'},{name:'mgmt0',speed:'1G',mgmt:true}],poe:false},
    {value:'n3k-c3048pq',label:'Nexus 3048TP-1GE (48×1G + 4×10G SFP+)',ports:[{prefix:'Ethernet1/',from:1,to:48,speed:'1G'},{prefix:'Ethernet1/',from:49,to:52,speed:'10G'},{name:'mgmt0',speed:'1G',mgmt:true}],poe:false},
    {value:'n5k-c5596up',label:'Nexus 5596UP (48 個固定 unified 埠；3 個擴充槽模組未列)',ports:[{prefix:'Ethernet1/',from:1,to:48,speed:'10G'},{name:'mgmt0',speed:'1G',mgmt:true}],poe:false},
    {value:'n7k-c7018',label:'Nexus 7018 (模組化機箱；以插槽 1 的 48×10G 線卡示意，依實際線卡調整)',ports:[{prefix:'Ethernet1/',from:1,to:48,speed:'10G'},{name:'mgmt0',speed:'1G',mgmt:true}],poe:false},
    {value:'n9k-c9396tx',label:'Nexus 9396TX (48×1/10GBASE-T；Eth2/1-12 為 N9K-M12PQ 上行模組 12×40G)',ports:[{prefix:'Ethernet1/',from:1,to:48,speed:'10G'},{prefix:'Ethernet2/',from:1,to:12,speed:'40G'},{name:'mgmt0',speed:'1G',mgmt:true}],poe:false},
    {value:'n5k-c5548p-10ge',label:'Nexus 5548P (32×1/10G SFP+；擴充模組未列)',ports:[{prefix:'Ethernet1/',from:1,to:32,speed:'10G'},{name:'mgmt0',speed:'1G',mgmt:true}],poe:false},
    {value:'n7k-c7010',label:'Nexus 7010 (模組化機箱；以插槽 1 的 48×10G 線卡示意，依實際線卡調整)',ports:[{prefix:'Ethernet1/',from:1,to:48,speed:'10G'},{name:'mgmt0',speed:'1G',mgmt:true}],poe:false},
    {value:'n9k-c9372px',label:'Nexus 9372PX (48×10G SFP+ + 6×40G QSFP+)',ports:[{prefix:'Ethernet1/',from:1,to:48,speed:'10G'},{prefix:'Ethernet1/',from:49,to:54,speed:'40G'},{name:'mgmt0',speed:'1G',mgmt:true}],poe:false},
    {value:'n9k-c93180yc-ex',label:'Nexus 93180YC-EX (48x10/25G+6x100G，現行世代)',ports:[
      {prefix:'Ethernet1/',from:1,to:48,speed:'25G'},
      {prefix:'Ethernet1/',from:49,to:54,speed:'100G'},
      {name:'mgmt0',speed:'1G',mgmt:true}],poe:false},
    {value:'n9k-c9336c-fx2',label:'Nexus 9336C-FX2 (36x40/100G，光纖骨幹)',ports:[
      {prefix:'Ethernet1/',from:1,to:36,speed:'100G'},
      {name:'mgmt0',speed:'1G',mgmt:true}],poe:false},
  ],
  'dell-os10':[
    {value:'s3048-on',label:'Dell S3048-ON (48×1G+4×10G)',ports:[
      {prefix:'ethernet1/1/',from:1,to:48,speed:'1G'},
      {prefix:'ethernet1/1/',from:49,to:52,speed:'10G'},
      {name:'management1/1/1',speed:'1G',mgmt:true}],poe:false},
    {value:'s4048-on',label:'Dell S4048-ON (48×10G+6×40G)',ports:[
      {prefix:'ethernet1/1/',from:1,to:48,speed:'10G'},
      {prefix:'ethernet1/1/',from:49,to:54,speed:'40G'},
      {name:'management1/1/1',speed:'1G',mgmt:true}],poe:false},
    // S5248F-ON：埠 49-52 為 2 個 QSFP28-DD（各 2 埠），53-56 為 4 個 QSFP28（Dell 部署指南與社群官方回覆，XN169）
    {value:'s5248f-on',label:'Dell PowerSwitch S5248F-ON (48×25G SFP28 + 2×QSFP28-DD〔49-52〕+ 4×100G QSFP28〔53-56〕)',ports:[
      {prefix:'ethernet1/1/',from:1,to:48,speed:'25G'},
      {prefix:'ethernet1/1/',from:49,to:56,speed:'100G'},
      {name:'management1/1/1',speed:'1G',mgmt:true}],poe:false},
    {value:'z9332f-on',label:'Dell PowerSwitch Z9332F-ON (32×400G QSFP56-DD，以 100G 表示；另 2×SFP+ 未列)',ports:[
      {prefix:'ethernet1/1/',from:1,to:32,speed:'100G'},
      {name:'management1/1/1',speed:'1G',mgmt:true}],poe:false},
  ],
  arista:[
    {value:'7010tx-48',label:'Arista 7010TX-48 (48×1G)',ports:[
      {prefix:'Ethernet',from:1,to:48,speed:'1G'},
      {name:'Management1',speed:'1G',mgmt:true}],poe:false},
    // 720XP-48ZC2：依 Arista datasheet／快速安裝指南，40×2.5G PoE+＋8×5G PoE（60W）＋4×25G SFP＋2×100G QSFP；
    // 埠號分組與 QSFP 名稱與 NetBox devicetype-library（CCS-720XP-48ZC2-F）相同（XN176）
    {value:'720xp-48zc2',label:'Arista 720XP-48ZC2 (40×2.5G + 8×5G PoE + 4×25G SFP + 2×100G QSFP)',ports:[
      {prefix:'Ethernet',from:1,to:40,speed:'2.5G'},
      {prefix:'Ethernet',from:41,to:48,speed:'5G'},
      {prefix:'Ethernet',from:49,to:52,speed:'25G'},
      {prefix:'Ethernet',from:53,to:54,speed:'100G',suffix:'/1'},
      {name:'Management1',speed:'1G',mgmt:true}],poe:true,poeRange:[1,48]},
    {value:'7050sx3-48yc8',label:'Arista 7050SX3-48YC8 (48×25G+8×100G)',ports:[{prefix:'Ethernet',from:1,to:48,speed:'25G'},{prefix:'Ethernet',from:49,to:56,speed:'100G',suffix:'/1'},{name:'Management1',speed:'1G',mgmt:true}],poe:false},
    {value:'7060cx2-32s',label:'Arista 7060CX2-32S (32×100G + 2×10G)',ports:[{prefix:'Ethernet',from:1,to:32,speed:'100G',suffix:'/1'},{prefix:'Ethernet',from:33,to:34,speed:'10G'},{name:'Management1',speed:'1G',mgmt:true}],poe:false},
    // 750X 模組化機箱（XN176，依 NetBox devicetype-library CCS-755：插槽 1／2 為監控引擎〔CCS-750-SUP25：Ethernet{插槽}/1-4 SFP28、
    // Management{插槽}/1〕、插槽 3 起為線卡〔Ethernet{插槽}/1-48〕）；以插槽 1 的監控引擎＋插槽 3 的線卡示意
    {value:'arista750-48-1g',label:'Arista 750X 校園存取 (模組化，插槽 3 線卡 48×1G PoE + 插槽 1 監控引擎 4×25G SFP28)',ports:[
      {prefix:'Ethernet3/',from:1,to:48,speed:'1G'},
      {prefix:'Ethernet1/',from:1,to:4,speed:'25G'},
      {name:'Management1/1',speed:'1G',mgmt:true}],poe:true,poeRange:[1,48]},
    {value:'arista750-48-10g',label:'Arista 750X 校園存取 (模組化，插槽 3 線卡 48×Multi-Gig 10G PoE + 插槽 1 監控引擎 4×25G SFP28)',ports:[
      {prefix:'Ethernet3/',from:1,to:48,speed:'10G'},
      {prefix:'Ethernet1/',from:1,to:4,speed:'25G'},
      {name:'Management1/1',speed:'1G',mgmt:true}],poe:true,poeRange:[1,48]},
  ],
  brocade:[
    // ICX 埠號為 單元/槽/埠（XN169，依 Ruckus 硬體安裝手冊）：前方存取埠在 slot 1，上行／堆疊埠在 slot 2、3
    // ICX7150-48P：2×1G RJ-45 上行在 slot 2、4×10G SFP+ 上行／堆疊在 slot 3
    {value:'icx7150-48p',label:'Ruckus ICX7150-48P (48×1G PoE+ + 2×1G RJ-45 + 4×10G SFP+ Uplink)',ports:[
      {prefix:'1/1/',from:1,to:48,speed:'1G'},
      {prefix:'1/2/',from:1,to:2,speed:'1G'},
      {prefix:'1/3/',from:1,to:4,speed:'10G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:true,poeRange:[1,48]},
    {value:'icx7250-48',label:'Ruckus ICX7250-48 (48×1G + 8×10G SFP+ Uplink)',ports:[
      {prefix:'1/1/',from:1,to:48,speed:'1G'},
      {prefix:'1/2/',from:1,to:8,speed:'10G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:false},
    // ICX7550-48：2×QSFP（40G／100G）上行／堆疊在 slot 2；選購上行模組另佔一槽，未列
    {value:'icx7550-48',label:'Ruckus ICX7550-48 (48×1G + 2×40/100G QSFP；選購上行模組未列)',ports:[
      {prefix:'1/1/',from:1,to:48,speed:'1G'},
      {prefix:'1/2/',from:1,to:2,speed:'100G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:false},
    // ICX7650-48P：依官方 datasheet，前方 48×1G RJ-45（40 埠 PoE+、8 埠另支援 UPoE／PoH），48P 只支援後方 2×40G 上行；
    // 後方模組在 FastIron 編號為 1/3/x（實際 show interfaces stack-ports 輸出）。前方選購模組只在後方用於堆疊時啟用，不列入
    {value:'icx7650-48p',label:'Ruckus ICX7650-48P (48×1G PoE+ + 2×40G Rear Uplink)',ports:[
      {prefix:'1/1/',from:1,to:48,speed:'1G'},
      {prefix:'1/3/',from:1,to:2,speed:'40G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:true,poeRange:[1,48]},
    {value:'icx8200-24',label:'Ruckus ICX8200-24 (24×1G + 4×25G SFP28 Uplink，ICX7150 後繼機)',ports:[
      {prefix:'1/1/',from:1,to:24,speed:'1G'},
      {prefix:'1/2/',from:1,to:4,speed:'25G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:false},
    {value:'icx8200-48p',label:'Ruckus ICX8200-48PF2 (48×1G PoE+ 740W + 4×25G SFP28 Uplink)',ports:[
      {prefix:'1/1/',from:1,to:48,speed:'1G'},
      {prefix:'1/2/',from:1,to:4,speed:'25G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:true,poeRange:[1,48]},
  ],
  alcatel:[
    // OmniSwitch：依 ALE 官方 datasheet（XN169）。OS6560-P24X4 的上行埠順序依 NetBox devicetype-library（XN176）：25-26 為 1G SFP、27-30 為 SFP+
    {value:'os6560-p24',label:'Alcatel OmniSwitch 6560-P24X4 (24×1G PoE+ + 2×1G SFP + 4×10G SFP+)',ports:[
      {prefix:'1/1/',from:1,to:24,speed:'1G'},
      {prefix:'1/1/',from:25,to:26,speed:'1G'},
      {prefix:'1/1/',from:27,to:30,speed:'10G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:true,poeRange:[1,24]},
    {value:'os6860-24',label:'Alcatel OmniSwitch 6860-24 (24×1G + 4×10G SFP+)',ports:[
      {prefix:'1/1/',from:1,to:24,speed:'1G'},
      {prefix:'1/1/',from:25,to:28,speed:'10G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:false},
    // OS6900-X20：20×SFP+ 加一個選購擴充模組槽（已停售，現行 datasheet 未收），模組埠未列
    {value:'os6900-x20',label:'Alcatel OmniSwitch 6900-X20 (20×10G SFP+；選購擴充模組未列)',ports:[
      {prefix:'1/1/',from:1,to:20,speed:'10G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:false},
    {value:'os6900-x24c2',label:'Alcatel OmniSwitch 6900-X24C2 (26×SFP+ 1G/10G + 2×QSFP28 100G)',ports:[
      {prefix:'1/1/',from:1,to:26,speed:'10G'},
      {prefix:'1/1/',from:27,to:28,speed:'100G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:false},
    // OS2360-P24：24×PoE＋2×1G SFP 上行＋2×SFP+（1G 上行或 10G 堆疊）
    {value:'os2360-p24',label:'Alcatel OmniSwitch 2360-P24 (24×1G PoE + 2×1G SFP + 2×SFP+ 1G 上行／10G 堆疊)',ports:[
      {prefix:'1/1/',from:1,to:24,speed:'1G'},
      {prefix:'1/1/',from:25,to:28,speed:'1G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:true,poeRange:[1,24]},
    // OS6870-24：24×1G RJ-45（無 PoE）＋4×SFP28＋2×QSFP28（40/100G VFL／堆疊）
    {value:'os6870-24',label:'Alcatel OmniSwitch 6870-24 (24×1G + 4×25G SFP28 + 2×40/100G QSFP28；QSFP28 編號未查證)',ports:[
      {prefix:'1/1/',from:1,to:24,speed:'1G'},
      {prefix:'1/1/',from:25,to:28,speed:'25G'},
      {prefix:'1/1/',from:29,to:30,speed:'100G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:false},
  ],
  extreme:[
    {value:'x440-g2-48p',label:'Extreme Summit X440-G2-48p (48×1G PoE+ + 4×10G Uplink)',ports:[{prefix:'',from:1,to:48,speed:'1G'},{prefix:'',from:49,to:52,speed:'10G'},{name:'mgmt',speed:'1G',mgmt:true}],poe:true,poeRange:[1,48]},
    {value:'x670-g2-48x',label:'Extreme Summit X670-G2-48x (48×10G + 4×40G Uplink)',ports:[{prefix:'',from:1,to:48,speed:'10G'},{prefix:'',from:49,to:52,speed:'40G'},{name:'mgmt',speed:'1G',mgmt:true}],poe:false},
    // 5420F（documentation.extremenetworks.com 5420 Series Installation Guide）：另有 2×SFP-DD 堆疊埠未列；
    // 單機埠號不帶「單元:」前綴（同 X440／X670，NetBox 同）
    {value:'x5420-24',label:'ExtremeSwitching 5420F-24T-4XE (24×1G + 4×1/10G SFP+；2×SFP-DD 堆疊埠未列)',ports:[
      {prefix:'',from:1,to:24,speed:'1G'},
      {prefix:'',from:25,to:28,speed:'10G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:false},
    {value:'x5420-48p',label:'ExtremeSwitching 5420F-48P-4XE (48×1G 802.3at PoE+ + 4×1/10G SFP+；2×SFP-DD 堆疊埠未列)',ports:[
      {prefix:'',from:1,to:48,speed:'1G'},
      {prefix:'',from:49,to:52,speed:'10G'},
      {name:'mgmt',speed:'1G',mgmt:true}],poe:true,poeRange:[1,48]},
  ],
  procurve:[
    {value:'aruba2530-24g',label:'Aruba 2530-24G (J9776A)',ports:[
      {prefix:'',from:1,to:24,speed:'1G'},
      {prefix:'',from:25,to:28,speed:'1G'}],poe:false},
    {value:'aruba2930f-24g',label:'Aruba 2930F-24G-4SFP+ (JL253A)',ports:[
      {prefix:'',from:1,to:24,speed:'1G'},
      {prefix:'',from:25,to:28,speed:'10G'}],poe:false},
    {value:'aruba2930f-48g',label:'Aruba 2930F-48G-4SFP+ (JL254A)',ports:[
      {prefix:'',from:1,to:48,speed:'1G'},
      {prefix:'',from:49,to:52,speed:'10G'}],poe:false},
    {value:'aruba2540-24g',label:'Aruba 2540 24G 4SFP+ (JL354A)',ports:[
      {prefix:'',from:1,to:24,speed:'1G'},
      {prefix:'',from:25,to:28,speed:'10G'}],poe:false},
    {value:'aruba2540-48g',label:'Aruba 2540 48G 4SFP+ (JL355A)',ports:[
      {prefix:'',from:1,to:48,speed:'1G'},
      {prefix:'',from:49,to:52,speed:'10G'}],poe:false},
  ],
  routeros:[
    {value:'rb4011',label:'MikroTik RB4011iGS+ (10×1G + 1×SFP+)',ports:[
      {prefix:'ether',from:1,to:10,speed:'1G'},
      {prefix:'sfp-sfpplus',from:1,to:1,speed:'10G'}],poe:false},
    {value:'ccr1072',label:'MikroTik CCR1072-1G-8S+ (8×SFP+ + 1×1G)',ports:[
      {prefix:'ether',from:1,to:1,speed:'1G'},
      {prefix:'sfp-sfpplus',from:1,to:8,speed:'10G'}],poe:false},
    {value:'crs328-24p',label:'MikroTik CRS328-24P-4S+RM (24×1G PoE+ + 4×SFP+ 10G)',ports:[
      {prefix:'ether',from:1,to:24,speed:'1G'},
      {prefix:'sfp-sfpplus',from:1,to:4,speed:'10G'}],poe:true,poeRange:[1,24]},
    {value:'rb5009',label:'MikroTik RB5009UG+S+IN (7×1G + 1×2.5G + 1×SFP+ 10G)',ports:[
      {prefix:'ether',from:1,to:7,speed:'1G'},
      {name:'ether8',speed:'2.5G'},
      {prefix:'sfp-sfpplus',from:1,to:1,speed:'10G'}],poe:false},
    {value:'ccr2216',label:'MikroTik CCR2216-1G-12XS-2XQ (1×1G + 12×SFP28 up to 25G + 2×QSFP28 100G)',ports:[
      {name:'ether1',speed:'1G'},
      {prefix:'sfp28-',from:1,to:12,speed:'25G'},
      // RouterOS 的 QSFP28 介面為 qsfp28-<cage>-<子埠>，100G 單一連線設定在第一個子埠（help.mikrotik.com MTU 頁、wired interface compatibility）
      {name:'qsfp28-1-1',speed:'100G'},{name:'qsfp28-2-1',speed:'100G'}],poe:false},
    {value:'crs112-8g4s',label:'MikroTik CRS112-8G-4S-IN (入門級，8×1G + 4×SFP 1G)',ports:[
      {prefix:'ether',from:1,to:8,speed:'1G'},
      {prefix:'sfp',from:9,to:12,speed:'1G'}],poe:false},  // CRS112 的 SFP 預設名稱為 sfp9-sfp12（help.mikrotik.com MTU 頁）
  ],
  // 2026-07-29 對外查證官方 Ruijie Networks 產品頁/datasheet 後新增：入門 access
  // （RG-S2928G-E V3，官方確認支援 VSU）／中階 aggregation（RG-S5750C-28GT4XS-H）／
  // 高階資料中心（RG-S6220-48XS6QXS-H，官方確認支援 VSU 2.0）三款代表機型
  ruijie:[
    {value:'s2928g-e',label:'Ruijie RG-S2928G-E V3 (入門級，24×1G + 4×SFP 1G，支援VSU；介面編號未查證)',ports:[
      {prefix:'GigabitEthernet 0/',from:1,to:28,speed:'1G'}],poe:false},
    {value:'s5750c-28gt4xs',label:'Ruijie RG-S5750C-28GT4XS-H (中階匯聚，28×1G + 4×SFP+ 10G；介面編號未查證)',ports:[
      {prefix:'GigabitEthernet 0/',from:1,to:28,speed:'1G'},
      {prefix:'TenGigabitEthernet 0/',from:1,to:4,speed:'10G'}],poe:false},
    {value:'s6220-48xs6qxs',label:'Ruijie RG-S6220-48XS6QXS-H (高階資料中心，48×10G SFP+ + 6×40G QSFP+，支援VSU 2.0；介面編號未查證)',ports:[
      {prefix:'TenGigabitEthernet 0/',from:1,to:48,speed:'10G'},
      {prefix:'FortyGigabitEthernet 0/',from:1,to:6,speed:'40G'}],poe:false},
  ],
  netgear:[
    {value:'m4300-28g',label:'Netgear M4300-28G (24×1G + 2×10GBASE-T + 2×SFP+ 10G)',ports:[
      {prefix:'1/0/',from:1,to:24,speed:'1G'},
      {prefix:'1/0/',from:25,to:28,speed:'10G'}],poe:false},  // M4300 介面為 unit/slot/port（固定埠 slot 0，Netgear M4300 CLI 手冊）
    {value:'m4300-52g',label:'Netgear M4300-52G (48×1G + 2×10GBASE-T + 2×SFP+ 10G)',ports:[
      {prefix:'1/0/',from:1,to:48,speed:'1G'},
      {prefix:'1/0/',from:49,to:52,speed:'10G'}],poe:false},
  ],
  edgeswitch:[
    {value:'es-24-250w',label:'Ubiquiti EdgeSwitch ES-24-250W (24×1G PoE+ + 2×SFP)',ports:[
      {prefix:'0/',from:1,to:24,speed:'1G'},
      {prefix:'0/',from:25,to:26,speed:'1G'}],poe:true,poeRange:[1,24]},
    {value:'es-48-500w',label:'Ubiquiti EdgeSwitch ES-48-500W (48×1G PoE+ + 2×SFP + 2×SFP+ 10G)',ports:[
      {prefix:'0/',from:1,to:48,speed:'1G'},
      {prefix:'0/',from:49,to:50,speed:'1G'},
      {prefix:'0/',from:51,to:52,speed:'10G'}],poe:true,poeRange:[1,48]},
  ],
  planet:[
    {value:'sgs-6341-24t4x',label:'Planet SGS-6341-24T4X (24×1G + 4×SFP+ 10G)',ports:[
      {prefix:'ethernet 1/0/',from:1,to:24,speed:'1G'},
      {prefix:'ethernet 1/0/',from:25,to:28,speed:'10G'}],poe:false},
    {value:'sgs-6341-48t4x',label:'Planet SGS-6341-48T4X (48×1G + 4×SFP+ 10G)',ports:[
      {prefix:'ethernet 1/0/',from:1,to:48,speed:'1G'},
      {prefix:'ethernet 1/0/',from:49,to:52,speed:'10G'}],poe:false},
  ],
};
