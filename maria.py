# -*- coding: utf-8 -*-

import wx
import threading
import binascii
import time
import datetime
import socket
import traceback
import pickle
from scapy.all import *
import queue
import gc

import const

MARiA_MAJOR_VERSION = 0
MARiA_MINOR_VERSION = 1
MARiA_MAJOR_REVISION = 4
MARiA_VERSION = "v{}.{}.{}".format(MARiA_MAJOR_VERSION, MARiA_MINOR_VERSION, MARiA_MAJOR_REVISION)

Configuration = {"Window_XPos": 0, "Window_YPos": 0, "Width": 800, "Height": 500, "Show_OtherPacket": 1}
dummy_mob = ["unknown.gat",0,0,0,0,"No Mob Name",0,0,0,0,0]
dummy_npc = ["unknown.gat",0,0,0,"No NPC Name",0,0]
dummy_chr = {'Char_id': 0, 'Char_Name': 0, "BaseExp": -1, "JobExp": -1, "Zeny": -1}
dummy_inv = {'Nameid': 0, 'Amount': 0}
Packetlen = {}
IgnorePacket = {}
chrselect = []
chrselect = dummy_chr
chrdata = {"aid": 0, "name": "unknown name", "mapname": "unknown.gat", "x": 0, "y": 0, "BaseExp": -1, "JobExp": -1, "Zeny": -1}
mobdata = {}
mobdata.setdefault('5121',{})
mobdata['5121'].setdefault(0,{})
mobdata['5121'][0] = dummy_mob
npcdata = {}
npcdata.setdefault('5121',{})
npcdata['5121'].setdefault(0,{})
npcdata['5121'][0] = dummy_npc
warpnpc = {}
warpnpc.setdefault('5121',{})
warpnpc['5121'].setdefault(0,{})
warpnpc['5121'][0] = "dummy"
inventory = {}
inventory.setdefault('item',{})
inventory['item'].setdefault(0,{})
inventory['item'][0] = dummy_inv
waitingroom = {}
mobskill = {}
mobskill.setdefault('0',{})
mobskill['0'].setdefault('0',{})
mobskill['0']['0'] = [0,0,0,0,0,0,0,0,"","",0]

TargetIP = 0
IgnorePacketAll = 0

MAX_PACKET_DB = 0x0C10

SkillName = const.SKILLNAME
EFST = const.EFST
NPC = const.NPC
MOB = const.MOB
UNITID = const.UNITID
RANDOPT = const.RANDOPT

recv_q = queue.Queue()

RFIFOS = lambda p, pos1, pos2: p[pos1*2:pos2*2]
RFIFOB = lambda p, pos: int(p[pos*2:pos*2+2],16)
RFIFOW = lambda p, pos: int(p[pos*2+2:pos*2+4]+p[pos*2:pos*2+2],16)
RFIFOL = lambda p, pos: int(p[pos*2+6:pos*2+8]+p[pos*2+4:pos*2+6]+p[pos*2+2:pos*2+4]+p[pos*2:pos*2+2],16)
RFIFOQ = lambda p, pos: int(p[pos*2+14:pos*2+16]+p[pos*2+12:pos*2+14]+p[pos*2+10:pos*2+12]+p[pos*2+8:pos*2+10]+p[pos*2+6:pos*2+8]+p[pos*2+4:pos*2+6]+p[pos*2+2:pos*2+4]+p[pos*2:pos*2+2],16)
RFIFOPOSX = lambda p, pos: (int(p[pos*2:pos*2+2],16)<<2) + ((int(p[pos*2+2:pos*2+4],16)&0xc0)>>6)
RFIFOPOSY = lambda p, pos: ((int(p[pos*2+2:pos*2+4],16)&0x3f)<<4) + ((int(p[pos*2+4:pos*2+6],16)&0xF0)>>4)
RFIFOPOSD = lambda p, pos: (int(p[pos*2+4:pos*2+6],16)&0xF)

RFIFOPOS2X = lambda p, pos: ((int(p[pos*2+4:pos*2+6],16)&0xF)<<6) + ((int(p[pos*2+6:pos*2+8],16)&0xFC)>>2)
RFIFOPOS2Y = lambda p, pos: ((int(p[pos*2+6:pos*2+8],16)&0x03)<<8) + (int(p[pos*2+8:pos*2+10],16))

gettick = lambda : int(time.time() * 1000)
getskill = lambda n: n if not n in SkillName else SkillName[n]
getefst = lambda n: n if not n in EFST else EFST[n]
getunitid = lambda n: n if not n in UNITID else UNITID[n]
getrandopt = lambda n: n if not n in RANDOPT else RANDOPT[n]

def read_config_db():
	path = './Config.txt'

	with open(path) as f:
		for s_line in f:
			if s_line[:2] == "//":
				continue
			elif s_line[:1] == "\n":
				continue
			else:
				l = s_line.split('\t')
				if len(l) >= 2:
					if l[0] in Configuration:
						Configuration[str(l[0])] = int(l[1])

def read_packet_db():
	path = './PacketLength.txt'

	with open(path) as f:
		for s_line in f:
			if s_line[:2] == "//":
				continue
			elif s_line[:1] == "\n":
				continue
			else:
				l = s_line.split(' ')
				if len(l) >= 2:
					Packetlen[int(l[0],16)] = int(l[1])
				else:
					l = s_line.split(',')
					if len(l) >= 2:
						Packetlen[int(l[0],16)] = int(l[1])

def read_ignore_db():
	path = './Ignore.txt'

	with open(path) as f:
		for s_line in f:
			if s_line[:2] == "//":
				continue
			elif s_line[:1] == "\n":
				continue
			else:
				l = s_line.split(' ')
				if len(l) >= 2:
					if int(l[0],16) == 0xffff:
						global IgnorePacketAll
						IgnorePacketAll = int(l[1])
					else:
						IgnorePacket[int(l[0],16)] = int(l[1])

def save_configuration():
	path = './Config.txt'

	savedata = []
	with open(path) as f:
		for s_line in f:
			if s_line[:2] == "//":
				savedata.append(s_line)
			elif s_line[:1] == "\n" or not s_line:
				savedata.append("\n")
			else:
				sp = s_line.split('\t')
				if len(sp) >= 2:
					if sp[0] in Configuration:
						sp[1] = str(Configuration[sp[0]])
				sp2 = '\t'.join(sp)
				savedata.append(sp2)
	s_lines = ['' if '\n' in s else s for s in savedata]
	sp = '\n'.join(s_lines)
	with open(path, mode="w") as f:
		f.write(sp)

class MARiA_Catch(threading.Thread):
	def __init__(self):
		threading.Thread.__init__(self)
		self.charport = 6121
		self.mapport = 5121
		self.pause_flag = True

	def setport(self, num1, num2):
		self.charport = num1
		self.mapport = num2

	def run(self):
		conf.layers.filter ([IP, TCP])
		sniff (filter = "ip host "+TargetIP, prn=self.OnCatch, count=0)

	def readpause(self):
		return self.pause_flag

	def c_pause(self,flag):
		self.pause_flag = flag

	def is_this_target_packet(self, packet):
		return TCP in packet and (packet[TCP].sport == self.charport or packet[TCP].sport == self.mapport)

	def OnHexEx(self,x):
		s = ""
		x = bytes_encode(x)
		x_len = len(x)
		i = 0
		while i < x_len:
			for j in range(16):
				if i + j < x_len:
					s += "%02x" % orb(x[i + j])
			i += 16
		return s

	def OnCatch(self, packet):
		if self.pause_flag == False:
			if self.is_this_target_packet(packet) == True:
				if Raw in packet:
					raw = packet.lastlayer()
					if not recv_q.full():
						recv_q.put(self.OnHexEx(raw), block=False)
		else:
			pass

class MARiA_Frame(wx.Frame):
	Started		= False
	Speed		= 25
	ID_TIMER	= 1
	buf			= ""
	bufcnt		= 0
	prev_num	= 0
	logout_mode	= 0
	tmp_id		= 0
	timerlock	= 0
	timerlockcnt= 0
	packet_lasttick = 0
	th = MARiA_Catch()
	th.setDaemon(True)

	def __init__(self, parent, id, title):
		wx.Frame.__init__(
			self, 
			parent, 
			id,
			title=title, 
			pos=(Configuration['Window_XPos'],Configuration['Window_YPos']),
			size=(Configuration['Width'],Configuration['Height']))

		self.timer = wx.Timer(self, MARiA_Frame.ID_TIMER)

		sb = self.CreateStatusBar()
		sb.SetFieldsCount(4)
		sb.SetStatusWidths([150, 130, 130, 120])
		sb.SetStatusText(chrdata['mapname']+':('+str(chrdata['x'])+', '+str(chrdata['y'])+")", 0)
		sb.SetStatusText('BaseExp: '+str(chrdata['BaseExp']), 1)
		sb.SetStatusText('JobExp: '+str(chrdata['JobExp']), 2)
		sb.SetStatusText('Zeny: '+str(chrdata['Zeny']), 3)
		self.statusbar = sb

		menubar = wx.MenuBar()
		file = wx.Menu()
		edit = wx.Menu()

		copybinary = file.Append(-1, "バイナリ窓コピー")
		copyscript = file.Append(-1, "スクリプト窓コピー")
		file.AppendSeparator()
		savefile = file.Append(-1, "データをファイルに保存")
		self.Bind(wx.EVT_MENU, self.OnSaveFile, savefile)
		loadfile = file.Append(-1, "ファイルからデータ読込")
		self.Bind(wx.EVT_MENU, self.OnLoadFile, loadfile)
		file.AppendSeparator()
		item_1 = wx.MenuItem(file, -1, 'Auriga', kind=wx.ITEM_RADIO)
		item_2 = wx.MenuItem(file, -1, 'rAthena:ToDo', kind=wx.ITEM_RADIO)
		item_3 = wx.MenuItem(file, -1, 'Hercules:ToDo', kind=wx.ITEM_RADIO)
		self.scripttimer = wx.MenuItem(file, -1, 'スクリプトタイマーを表示', kind=wx.ITEM_CHECK)
		self.hiddenbattle = wx.MenuItem(file, -1, '戦闘ログを非表示', kind=wx.ITEM_CHECK)
		item_5 = wx.MenuItem(file, -1, 'ToDo', kind=wx.ITEM_CHECK)
		file.Append(item_1)
		file.Append(item_2)
		file.Append(item_3)
		file.AppendSeparator()
		file.Append(self.scripttimer)
		file.Append(self.hiddenbattle)
		file.Append(item_5)

		reloadignore = edit.Append(-1, "IgnorePacket再読み込み")
		self.Bind(wx.EVT_MENU, self.OnReloadIgnore, reloadignore)

		reloadpacket = edit.Append(-1, "PacketLength再読み込み")
		self.Bind(wx.EVT_MENU, self.OnReloadPacket, reloadpacket)

		edit.AppendSeparator()

		clearcache = edit.Append(-1, "キャッシュクリア")
		self.Bind(wx.EVT_MENU, self.OnClearCache, clearcache)

		clearbuf = edit.Append(-1, "バッファクリア")
		self.Bind(wx.EVT_MENU, self.OnClearBuffer, clearbuf)

		clearbinary = edit.Append(-1, "バイナリ窓クリア")
		self.Bind(wx.EVT_MENU, self.OnClearBinary, clearbinary)

		clearscript = edit.Append(-1, "スクリプト窓クリア")
		self.Bind(wx.EVT_MENU, self.OnClearScript, clearscript)

		edit.AppendSeparator()

		moblist = edit.Append(-1, "モンスター生息情報統計")
		self.Bind(wx.EVT_MENU, self.OnMonsterList, moblist)
		mobskilllist = edit.Append(-1, "モンスタースキル情報統計")
		self.Bind(wx.EVT_MENU, self.OnMobSkillList, mobskilllist)

		menubar.Append(file, '&File')
		menubar.Append(edit, '&Edit')
		self.SetMenuBar(menubar)

		sp = wx.SplitterWindow(self,-1, style=wx.SP_LIVE_UPDATE)

		vbox = wx.BoxSizer(wx.VERTICAL)
		p1 = wx.Panel(sp, -1)

		hbox1 = wx.BoxSizer(wx.HORIZONTAL)

		ip_array = ["127.0.0.1"]
		st4 = wx.StaticText(p1, -1, 'Target IP:')
		hbox1.Add(st4, 0, wx.LEFT | wx.BOTTOM | wx.TOP, 2)
		self.addless = wx.ComboBox(
			p1,
			choices=ip_array,
			style=wx.CB_READONLY,
			size=(100,10))
		hbox1.Add(self.addless, 1, wx.EXPAND)
		self.Bind(wx.EVT_COMBOBOX, self.OnIPSelect, self.addless)

		st3 = wx.StaticText(p1, -1, 'Char Port:')
		hbox1.Add(st3, 0, wx.LEFT | wx.BOTTOM | wx.TOP, 2)
		self.charport = wx.TextCtrl(
			p1,
			-1,
			size=(20,10))
		self.charport.WriteText('6121')
		hbox1.Add(self.charport, 1, wx.EXPAND)

		st1 = wx.StaticText(p1, -1, 'Map Port:')
		hbox1.Add(st1, 0, wx.LEFT | wx.BOTTOM | wx.TOP, 2)
		self.mapport = wx.TextCtrl(
			p1,
			-1,
			size=(20,10))
		self.mapport.WriteText('5121')
		hbox1.Add(self.mapport, 1, wx.EXPAND)

		st2 = wx.StaticText(p1, -1, 'Active Start:')
		hbox1.Add(st2, 0, wx.RIGHT | wx.BOTTOM | wx.TOP, 2)
		self.button = wx.Button(
			p1,
			-1,
			'Start',
			size=(80,20))
		hbox1.Add(self.button,2)
		vbox.Add(hbox1, 0, wx.LEFT | wx.RIGHT | wx.TOP, 2)

		self.btext = wx.TextCtrl(
			p1,
			-1,
			style=wx.TE_MULTILINE | wx.TE_RICH2 | wx.HSCROLL)
		vbox.Add(self.btext, 1, wx.EXPAND)

		vbox2 = wx.BoxSizer(wx.VERTICAL)
		p2 = wx.Panel(sp, style=wx.SUNKEN_BORDER)
		self.text = wx.TextCtrl(
			p2,
			-1,
			style=wx.TE_MULTILINE | wx.TE_RICH2 | wx.HSCROLL)
		vbox2.Add(self.text, 1, wx.EXPAND)

		sp.SplitHorizontally(p1, p2)
		sp.SetMinimumPaneSize(110)
		self.button.Bind(wx.EVT_BUTTON, self.OnStart)
		self.Bind(wx.EVT_TIMER, self.OnTimer, id=MARiA_Frame.ID_TIMER)

		self.Bind(wx.EVT_CLOSE, self.OnClose)

		icon = wx.Icon(r"./icon.ico", wx.BITMAP_TYPE_ICO)
		self.SetIcon(icon)

		self.text.AppendText("setup...\n")

		host = socket.gethostname()
		global TargetIP
		ip_array2 = socket.gethostbyname_ex(host)[2]
		self.addless.Clear()
		self.addless.AppendItems(ip_array2)
		self.addless.SetSelection(0)
		TargetIP = ip_array2[0]

		self.text.AppendText("MARiA is Activeted, Target IP: " +TargetIP+ "\n")

		p1.SetSizer(vbox)
		p2.SetSizer(vbox2)
		self.Show(True)

	def OnStart(self, event):
		if self.Started == False:
			self.th.start()
			self.Started = True
		if self.th.readpause() == True:
			self.th.setport(int(self.charport.GetValue()), int(self.mapport.GetValue()))
			self.th.c_pause(False)
			self.timer.Start(MARiA_Frame.Speed)
			self.button.SetLabel("Stop")
			self.charport.Disable()
			self.mapport.Disable()
			self.addless.Disable()
		else:
			self.th.c_pause(True)
			self.timer.Stop()
			self.button.SetLabel("Start")
			self.charport.Enable()
			self.mapport.Enable()
			self.addless.Enable()

	def OnTimer(self, event):
		if event.GetId() == MARiA_Frame.ID_TIMER:
			if self.timerlock == 0:
				self.timerlockcnt = 0
				if not recv_q.empty():
					self.buf += recv_q.get()
					self.GetPacket()
			else:
				#ロックされてるときはカウンタをあげる
				self.timerlockcnt += 1
				if self.timerlockcnt >= 20:	#デッドロックの予感
					self.timerlock		= 0
					self.timerlockcnt	= 0
					self.BufferReset()
					print("DeadLock buf Clear\n")
		else:
			event.Skip()

	def OnClose(self, event):
		pos = self.GetScreenPosition()
		size = self.GetSize()
		Configuration["Window_XPos"] = pos[0]
		Configuration["Window_YPos"] = pos[1]
		Configuration["Width"] = size[0]
		Configuration["Height"] = size[1]
		save_configuration()
		event.Skip()

	def OnReloadPacket(self, event):
		global Packetlen
		Packetlen.clear()
		Packetlen = {}
		read_packet_db()
		self.text.AppendText("@reload packetlength done.\n")

	def OnReloadIgnore(self, event):
		global IgnorePacket
		global IgnorePacketAll
		IgnorePacket.clear()
		IgnorePacket = {}
		IgnorePacketAll = 0
		read_ignore_db()
		self.text.AppendText("@reload ignorepacket done.\n")

	def OnClearCache(self, event):
		global chrdata
		chrdata.clear()
		chrdata = {"aid": 0, "name": "unknown name", "mapname": "unknown.gat", "x": 0, "y": 0, "BaseExp": 0, "JobExp": 0, "Zeny": 0}
		global mobdata
		mobdata.clear()
		mobdata = {}
		mobdata.setdefault('5121',{})
		mobdata['5121'].setdefault(0,{})
		mobdata['5121'][0] = dummy_mob
		global npcdata
		npcdata.clear()
		npcdata = {}
		npcdata.setdefault('5121',{})
		npcdata['5121'].setdefault(0,{})
		npcdata['5121'][0] = dummy_npc
		global warpnpc
		warpnpc.clear()
		warpnpc = {}
		warpnpc.setdefault('5121',{})
		warpnpc['5121'].setdefault(0,{})
		warpnpc['5121'][0] = "dummy"
		global mobskill
		mobskill.clear()
		mobskill = {}
		mobskill.setdefault('0',{})
		mobskill['0'].setdefault('0',{})
		mobskill['0']['0'] = [0,0,0,0,0,0,0,0,"","",0]

	def OnClearBuffer(self, event):
		self.BufferReset()

	def BufferReset(self):
		del self.buf
		gc.collect()
		self.buf = ""

	def OnClearBinary(self, event):
		self.btext.Clear()

	def OnClearScript(self, event):
		self.text.Clear()

	def OnMonsterList(self, event):
		mapmobs = {}
		mapmobs.setdefault('unknown.gat',{})
		mapmobs['unknown.gat'].setdefault(0,{})
		mapmobs['unknown.gat'][0] = ["unknown name", 0, 0, 0, 0, 0]
		for p in mobdata.keys():
			tmp_mobdata = sorted(mobdata[p])
			for aid in tmp_mobdata:
				if aid > 0:
					if mobdata[p][aid][MOB.MAP] in mapmobs.keys():
						if mobdata[p][aid][MOB.CLASS] == mapmobs[mobdata[p][aid][MOB.MAP]][len(mapmobs[mobdata[p][aid][MOB.MAP]])-1][1]:
							mapmobs[mobdata[p][aid][MOB.MAP]][len(mapmobs[mobdata[p][aid][MOB.MAP]])-1][2] += 1
							mapmobs[mobdata[p][aid][MOB.MAP]][len(mapmobs[mobdata[p][aid][MOB.MAP]])-1][4] = aid
							if mapmobs[mobdata[p][aid][MOB.MAP]][len(mapmobs[mobdata[p][aid][MOB.MAP]])-1][5] == 0 or mapmobs[mobdata[p][aid][MOB.MAP]][len(mapmobs[mobdata[p][aid][MOB.MAP]])-1][5] > mobdata[p][aid][MOB.SPAWNTICK]:
								mapmobs[mobdata[p][aid][MOB.MAP]][len(mapmobs[mobdata[p][aid][MOB.MAP]])-1][5] = mobdata[p][aid][MOB.SPAWNTICK]
						else:
							mapmobs[mobdata[p][aid][MOB.MAP]][len(mapmobs[mobdata[p][aid][MOB.MAP]])] = [ mobdata[p][aid][MOB.NAME],mobdata[p][aid][MOB.CLASS],1,aid,0,mobdata[p][aid][MOB.SPAWNTICK] ]
					else:
						mapmobs[mobdata[p][aid][MOB.MAP]] = { 0: [ mobdata[p][aid][MOB.NAME],mobdata[p][aid][MOB.CLASS],1,aid,0,mobdata[p][aid][MOB.SPAWNTICK] ] }
		for map in mapmobs.keys():
			self.text.AppendText("//------------------------------------------------------------\n")
			self.text.AppendText("// {}\n".format(map))
			for i in mapmobs[map]:
				if mapmobs[map][i][1] != 0:
					if mapmobs[map][i][4] != 0:
						self.text.AppendText("{},0,0,0,0\tmonster\t{}\t{},{},{},0,0\t// aid: {}-{}\n".format(map,mapmobs[map][i][0],mapmobs[map][i][1],mapmobs[map][i][2],mapmobs[map][i][5],mapmobs[map][i][3],mapmobs[map][i][4]))
					else:
						self.text.AppendText("{},0,0,0,0\tmonster\t{}\t{},{},{},0,0\t// aid: {}\n".format(map,mapmobs[map][i][0],mapmobs[map][i][1],mapmobs[map][i][2],mapmobs[map][i][5],mapmobs[map][i][3]))

	def OnMobSkillList(self, event):
		global mobskill
		#Table class { skillid { (int)MinRecasttime, LastCasttick, (int)Casttime, (bool)NowCasting, (bool)CastCancel, skilllv, div, val } }
		for class_ in mobskill.keys():
			if class_ != 0:
				for skillid in mobskill[class_].keys():
					casttype = 'yes'
					if mobskill[class_][skillid][4] == 0:
						casttype = 'no'
					skilllv = mobskill[class_][skillid][5]
					if skilllv == 65535:
						skilllv = mobskill[class_][skillid][6]
					if mobskill[class_][skillid][7] != 0:
						skilllv = mobskill[class_][skillid][7]
					if mobskill[class_][skillid][10] == 0:
						mode = 'any'
					elif mobskill[class_][skillid][10] == 1:
						mode = 'attack'
					elif mobskill[class_][skillid][10] == 2:
						mode = 'chase'
					elif mobskill[class_][skillid][10] == 3:
						mode = 'attack/chase'
					self.text.AppendText("{},{}＠{},{},{},{},2000,{},{},{},{},always,0,,,,,,\n".format(class_,mobskill[class_][skillid][9],getskill(skillid),mode,skillid,skilllv,mobskill[class_][skillid][2],mobskill[class_][skillid][0],casttype,mobskill[class_][skillid][8]))

	def OnSaveFile(self, event):
		try:
			with open('npc.md', 'wb') as f:
				pickle.dump(npcdata, f)
		except IOError:
			print('cannot open file npc.md')
		try:
			with open('mob.md', 'wb') as f:
				pickle.dump(mobdata, f)
		except IOError:
			print('cannot open file mob.md')
		try:
			with open('warp.md', 'wb') as f:
				pickle.dump(warpnpc, f)
		except IOError:
			print('cannot open file warp.md')

	def OnLoadFile(self, event):
		global npcdata
		global mobdata
		global warpnpc
		with open('npc.md', 'rb') as f:
			npcdata = pickle.load(f)
		with open('mob.md', 'rb') as f:
			mobdata = pickle.load(f)
		with open('warp.md', 'rb') as f:
			warpnpc = pickle.load(f)

	def CheckNearNPC(self, m, x, y):
		p = self.mapport.GetValue()
		if p in npcdata.keys():
			for aid in npcdata[p].keys():
				nm = npcdata[p][aid][NPC.MAP]
				class_ = npcdata[p][aid][NPC.CLASS]
				if nm == m and class_ == 45:
					nx = npcdata[p][aid][NPC.POSX]
					ny = npcdata[p][aid][NPC.POSY]
					if nx+2 >= x and nx-2 <= x and ny+2 >= y and ny-2 <= y:
						return aid
		return -1

	def OnIPSelect(self, event):
		global TargetIP
		obj = event.GetEventObject()
		TargetIP = obj.GetStringSelection()
		self.text.AppendText("MARiA is ReActivet, Target IP: " +TargetIP+ "\n")

	def GetPacket(self):
		buf = self.buf
		tick = gettick()
		self.timerlock = 1
		#print("getpacket start:{}".format(buf))
		while not buf == "":
			lasttick = gettick()
			if lasttick - tick > 5000:	#2500msを超えたら再帰
				print("GetPacket timeout lasttick:{}, tick:{}, buf:{}\n".format(lasttick, tick, buf))
				break
			total_len = len(buf)
			if total_len < 4:	#4文字以下なら
				print("GetPacket min buffer size, {}\n".format(buf))
				break
			num = RFIFOW(buf,0)
			if num in Packetlen.keys():
				packet_len = Packetlen[num]
			else:
				if num > MAX_PACKET_DB:
					snum = RFIFOW(buf,1)
					if snum in Packetlen.keys():
						print("[Info] unknown 1 byte skiped, result:",format(snum, '#06x'),", prev:",format(self.prev_num, '#06x'),", skiped byte: 0x",buf[:2],"\n")
						num = snum
						packet_len = Packetlen[num]
						buf = buf[2:]	#1byte skip
					else:
						print("[Error] unknown ultra high packet, id: ",format(num, '#06x'),", prev:",format(self.prev_num, '#06x'),", clear buf: ",buf,"\n")
						self.btext.AppendText("\nultrahigh_packetid_" + format(num, '#06x')+", prev:"+format(self.prev_num, '#06x'))
						buf = ""
						self.BufferReset()
						break
				else:
					snum = RFIFOW(buf,1)
					if snum in Packetlen.keys():
						print("[Info] unknown 1 byte skiped, result:",format(snum, '#06x'),", prev:",format(self.prev_num, '#06x'),", skiped byte: 0x",buf[:2],"\n")
						num = snum
						packet_len = Packetlen[num]
						buf = buf[2:]	#1byte skip
					else:
						print("[Error] unknown packet len: ",format(num, '#06x'),", prev:",format(self.prev_num, '#06x'),", set packet_len: 2\n")
						self.btext.AppendText("\nunknown_packetlength" + format(num, '#06x')+", prev:"+format(self.prev_num, '#06x'))
						packet_len = 2
			if packet_len == -1:
				packet_len = RFIFOW(buf,2)
				if packet_len <= 0:
					print("[Error] unknown packet len = 0: ",format(num, '#06x'),", prev:",format(self.prev_num, '#06x'),", clear buf: ",buf,"\n")
					self.btext.AppendText("\n"+format(num, '#06x')+" len=0: Please check PacketLength.txt. (prev:" + format(self.prev_num, '#06x')+")\n")
					buf = ''
					self.BufferReset()
					break
				elif packet_len >= 32000:
					print("[Error] big packet len: ",format(num, '#06x'),", prev:",format(self.prev_num, '#06x'),", clear buf: ",buf,"\n")
					self.btext.AppendText("\n"+format(num, '#06x')+" len=" +str(packet_len)+ ": Please check PacketLength.txt. (prev:" + format(self.prev_num, '#06x')+")\n")
					str_ = binascii.unhexlify(buf.encode('utf-8')).decode('cp932','ignore')
					self.text.AppendText(str_+ "\n")
					buf = ''
					self.BufferReset()
					break
			if packet_len*2 > total_len:	#パケット足りてない
				#if self.packet_lasttick > 0 and lasttick - self.packet_lasttick > 10000:	#10000ms待機しても続きが来ない
				#	print("[Error] packet time out, target:",format(num, '#06x'),", len: ",str(packet_len),", prev:",format(self.prev_num, '#06x'),", clear buf: ",buf,"\n")
				#	self.btext.AppendText("\n" + format(num, '#06x')+"(len = "+str(packet_len)+") Time out. Please check PacketLength.txt. (prev:" +format(self.prev_num, '#06x')+ ")")
				#	self.buf = buf = ''
				#	self.packet_lasttick = 0
				#elif self.packet_lasttick == 0:
				#	self.packet_lasttick = tick
				#print("[Waiting] packet waiting...",format(num, '#06x'),", len:",str(total_len),"/",str(packet_len*2),"\n")
				break
			if self.logout_mode >= 1:
				if buf[:4] == "0000":
					if total_len >= 10:
						if buf[:10] == "0000000000":
							if packet_len*2+10 < total_len:
								self.buf = buf = self.buf[10:]
							else:
								self.buf = buf = ''
						else:
							self.logout_mode = 0
					break
				else:
					self.logout_mode = 0
			if num == 0x229:
				if total_len >= packet_len*2+10:
					if buf[packet_len*2:packet_len*2+10] == "0000000000":
						packet_len += 5
				else:
					self.logout_mode = 1
			ignore_type = 0
			if num in IgnorePacket.keys():
				ignore_type = IgnorePacket[num]
			if (ignore_type&1 == 0 and IgnorePacketAll&1 == 0) or ignore_type&4:
				i = 0
				if self.btext.GetValue() != '':
					self.btext.AppendText('\n')
				self.btext.AppendText(format(num, '#06x')+": ")
				while i < packet_len*2:
					self.btext.AppendText(buf[i:i+2]+ ' ')
					i += 2
			if (ignore_type&2 == 0 and IgnorePacketAll&2 == 0) or ignore_type&8:
				try:
					if packet_len >= 2:
						self.ReadPacket(num, packet_len)
				except Exception as e:
					print(traceback.format_exc())
					buf = ''
					self.BufferReset()
					break
			self.prev_num = num
			if packet_len*2 < total_len:
				self.buf = buf = buf[packet_len*2:]
			else:
				self.buf = buf = ""
		self.timerlock = 0

	def ReadPacket(self, num, p_len):
		global mobskill
		n = hex(num)
		fd = self.buf[0:p_len*2]
		if num == 0x9fe:	#spawn
			if p_len > 83:
				type	= RFIFOB(fd,4)
				aid		= RFIFOL(fd,5)
				speed	= RFIFOW(fd,13)
				option	= RFIFOL(fd,19)
				view	= RFIFOW(fd,23)
				x		= RFIFOPOSX(fd,63)
				y		= RFIFOPOSY(fd,63)
				dir		= RFIFOPOSD(fd,63)
				if type==5 or type==6 or type==12:
					i = 83
					s = fd[i*2:p_len*2]
					opt = ""
					if option == 2:
						opt = "(hide)"
					elif option == 4:
						opt = "(cloaking)"
					s_len = len(s)
					if s_len > 46 and ((s[-2:] >= '80' and s[-2:] <= '9f') or (s[-2:] >= 'e0' and s[-2:] <= '9e')):
						s = s[:-2]
					s = binascii.unhexlify(s.encode('utf-8')).decode('cp932','ignore')
					s = "" if s[0] == '\0' else s
					p = self.mapport.GetValue()
					m = chrdata['mapname']
					if type == 5:
						if p in mobdata.keys():
							if aid in mobdata[p].keys():
								if mobdata[p][aid][MOB.DEADTICK] > 0:
									spawntick = gettick() - mobdata[p][aid][MOB.DEADTICK]
									if mobdata[p][aid][MOB.SPAWNTICK] == 0 or mobdata[p][aid][MOB.SPAWNTICK] > spawntick:
										mobdata[p][aid][MOB.SPAWNTICK] = spawntick
									mobdata[p][aid][MOB.DEADTICK] = 0
							else:
								cflag = 0
								if aid > 10000:
									cflag = len(self.text.GetValue())
								self.text.AppendText("@spawn(type: BL_MOB, ID: "+str(aid)+", speed: "+str(speed)+", option: "+str(hex(option))+", class: "+str(view)+", pos: (\"" +m+ "\","+str(x)+","+str(y)+"), dir: "+str(dir)+", name\""+ s +"\")\n")
								mobdata[p][aid] = [m,x,y,0,0,s,view,speed,0,0,0]
								if cflag > 0:
									self.text.SetStyle(cflag, len(self.text.GetValue()), wx.TextAttr("red", "blue"))
						else:
							self.text.AppendText("@spawn(type: BL_MOB, ID: "+str(aid)+", speed: "+str(speed)+", option: "+str(hex(option))+", class: "+str(view)+", pos: (\"" +m+ "\","+str(x)+","+str(y)+"), dir: "+str(dir)+", name\""+ s +"\")\n")
							mobdata[p] = { aid: [m,x,y,0,0,s,view,speed,0,0,0] }
					elif type == 6 or type==12:
						s3 = "script"
						if type==12:
							s3 = "script2"
						if p in npcdata.keys():
							if aid in npcdata[p].keys():
								if npcdata[p][aid][NPC.CLASS] != view:
									self.text.AppendText("@viewchange(setnpcdisplay \"{}\", {};\t// {}\n".format(s, view, aid))
								elif npcdata[p][aid][NPC.OPTION] != option:
									s2 = "@viewchange("
									if npcdata[p][aid][NPC.OPTION] == 2 or option == 2:
										s2 += "hideonnpc" if option == 2 else "hideoffnpc"
									elif npcdata[p][aid][NPC.OPTION] == 4 or option == 4:
										s2 += "cloakonnpc" if option == 4 else "cloakoffnpc"
									else:
										s2 += "hideoffnpc"
									s2 += " \""+s+"\";)\t// "+str(aid)
									npcdata[p][aid][NPC.OPTION] = option
									self.text.AppendText(s2+"\n")
							else:
								self.text.AppendText(m+","+ str(x) + ","+ str(y) +","+ str(dir) +"\t" +s3+ "\t"+ s +"\t"+ str(view) +",{/* "+ str(aid) +" "+opt+"*/}\n")
								npcdata[p][aid] = [m,x,y,dir,s,view,option]
						else:
							self.text.AppendText(m+","+ str(x) + ","+ str(y) +","+ str(dir) +"\t" +s3+ "\t"+ s +"\t"+ str(view) +",{/* "+ str(aid) +" "+opt+"*/}\n")
							npcdata[p] = { aid: [m,x,y,dir,s,view,option] }
						if type==12:
							self.text.AppendText("setnpcspeed {},\"{}\";\t// {}\n".format(speed,s,aid))
				elif type==9:
					self.text.AppendText("@spawn(type: BL_MERC, ID: "+str(aid)+", speed: "+str(speed)+", option: "+str(hex(option))+", class: "+str(view)+")\n")
		elif num == 0x9ff:	#idle
			if p_len >= 84:
				type	= RFIFOB(fd,4)
				aid		= RFIFOL(fd,5)
				speed	= RFIFOW(fd,13)
				option	= RFIFOL(fd,19)
				view	= RFIFOW(fd,23)
				x		= RFIFOPOSX(fd,63)
				y		= RFIFOPOSY(fd,63)
				dir		= RFIFOPOSD(fd,63)
				if type==5 or type==6 or type==12:
					opt = ""
					if option == 2:
						opt = "(hide)"
					elif option == 4:
						opt = "(cloaking)"
					if p_len == 84:
						s = " "
					else:
						i = 84
						s = fd[i*2:p_len*2]
						s_len = len(s)
						if s_len > 46 and ((s[-2:] >= '80' and s[-2:] <= '9f') or (s[-2:] >= 'e0' and s[-2:] <= '9e')):
							s = s[:-2]
						s = binascii.unhexlify(s.encode('utf-8')).decode('cp932','ignore')
						s = "" if s[0] == '\0' else s
					p = self.mapport.GetValue()
					m = chrdata['mapname']
					if type == 5:
						if p in mobdata.keys():
							if aid in mobdata[p].keys():
								if mobdata[p][aid][MOB.DEADTICK] > 0:
									spawntick = gettick() - mobdata[p][aid][MOB.DEADTICK]
									if mobdata[p][aid][MOB.SPAWNTICK] == 0 or mobdata[p][aid][MOB.SPAWNTICK] > spawntick:
										mobdata[p][aid][MOB.SPAWNTICK] = spawntick
									mobdata[p][aid][MOB.DEADTICK] = 0
							else:
								cflag = 0
								if aid > 10000:
									cflag = len(self.text.GetValue())
								self.text.AppendText("@spawn(type: BL_MOB, ID: "+str(aid)+", speed: "+str(speed)+", option: "+str(hex(option))+", class: "+str(view)+", pos: (\"" +m+ "\","+str(x)+","+str(y)+"), dir: "+str(dir)+", name\""+ s +"\")\n")
								mobdata[p][aid] = [m,x,y,0,0,s,view,speed,0,0,0]
								if cflag > 0:
									self.text.SetStyle(cflag, len(self.text.GetValue()), wx.TextAttr("red", "blue"))
						else:
							self.text.AppendText("@spawn(type: BL_MOB, ID: "+str(aid)+", speed: "+str(speed)+", option: "+str(hex(option))+", class: "+str(view)+", pos: (\"" +m+ "\","+str(x)+","+str(y)+"), dir: "+str(dir)+", name\""+ s +"\")\n")
							mobdata[p] = { aid: [m,x,y,0,0,s,view,speed,0,0,0] }
					elif type == 6 or type==12:
						s3 = "script"
						if type==12:
							s3 = "script2"
						if p in npcdata.keys():
							if aid in npcdata[p].keys():
								if npcdata[p][aid][NPC.CLASS] != view:
									self.text.AppendText("@viewchange(setnpcdisplay \"{}\", {};\t// {}\n".format(s, view, aid))
								elif npcdata[p][aid][NPC.OPTION] != option:
									s2 = "@viewchange("
									if npcdata[p][aid][NPC.OPTION] == 2 or option == 2:
										s2 += "hideonnpc" if option == 2 else "hideoffnpc"
									elif npcdata[p][aid][NPC.OPTION] == 4 or option == 4:
										s2 += "cloakonnpc" if option == 4 else "cloakoffnpc"
									else:
										s2 += "hideoffnpc"
									s2 += " \""+s+"\";)\t// "+str(aid)
									npcdata[p][aid][NPC.OPTION] = option
									self.text.AppendText(s2+"\n")
							else:
								self.text.AppendText(m+","+ str(x) + ","+ str(y) +","+ str(dir) +"\t" +s3+ "\t"+ s +"\t"+ str(view) +",{/* "+ str(aid) +" "+opt+"*/}\n")
								npcdata[p][aid] = [m,x,y,dir,s,view,option]
								if view < 45 or (view >= 4000 and view <= 4300):
									hair	= RFIFOW(fd,25)
									bottom	= RFIFOW(fd,35)
									top	= RFIFOW(fd,37)
									mid	= RFIFOW(fd,39)
									h_color	= RFIFOW(fd,41)
									c_color	= RFIFOW(fd,43)
									robe	= RFIFOW(fd,47)
									sex	= RFIFOB(fd,62)
									style	= RFIFOW(fd,82)
									self.text.AppendText("// Name Class Sex ClothColor HairStyle HairColor Helm1 Helm2 Helm3 robe style.\n")
									self.text.AppendText("OnInit:\n\tsetnpcdisplay \"{}\",{},{},{},{},{},{},{},{},{},{};\t// {}\n".format(npcdata[p][aid][NPC.NAME], view, sex, c_color, hair, h_color, top, mid, bottom, robe, style, aid))
						else:
							self.text.AppendText(m+","+ str(x) + ","+ str(y) +","+ str(dir) +"\t" +s3+ "\t"+ s +"\t"+ str(view) +",{/* "+ str(aid) +" "+opt+"*/}\n")
							npcdata[p] = { aid: [m,x,y,dir,s,view,option] }
						if type==12:
							self.text.AppendText("setnpcspeed {},\"{}\";\t// {}\n".format(speed,s,aid))
		elif num == 0x9fd:	#move
			if p_len > 90:
				type	= RFIFOB(fd,4)
				aid		= RFIFOL(fd,5)
				speed	= RFIFOW(fd,13)
				option	= RFIFOL(fd,19)
				view	= RFIFOW(fd,23)
				x		= RFIFOPOSX(fd,67)
				y		= RFIFOPOSY(fd,67)
				to_x	= RFIFOPOS2X(fd,67)
				to_y	= RFIFOPOS2Y(fd,67)
				if type==5 or type==6 or type==12:
					i = 90
					s = fd[i*2:p_len*2]
					opt = ""
					if option == 2:
						opt = "(hide)"
					elif option == 4:
						opt = "(cloaking)"
					s_len = len(s)
					if s_len > 46 and ((s[-2:] >= '80' and s[-2:] <= '9f') or (s[-2:] >= 'e0' and s[-2:] <= '9e')):
						s = s[:-2]
					s = binascii.unhexlify(s.encode('utf-8')).decode('cp932','ignore')
					p = self.mapport.GetValue()
					m = chrdata['mapname']
					if type == 5:
						if p in mobdata.keys():
							if aid in mobdata[p].keys():
								if mobdata[p][aid][MOB.DEADTICK] > 0:
									spawntick = gettick() - mobdata[p][aid][MOB.DEADTICK]
									if mobdata[p][aid][MOB.SPAWNTICK] == 0 or mobdata[p][aid][MOB.SPAWNTICK] > spawntick:
										mobdata[p][aid][MOB.SPAWNTICK] = spawntick
									mobdata[p][aid][MOB.DEADTICK] = 0
								mobdata[p][aid][MOB.POSX] = x
								mobdata[p][aid][MOB.POSY] = y
								mobdata[p][aid][MOB.POS2X] = to_x
								mobdata[p][aid][MOB.POS2Y] = to_y
							else:
								cflag = 0
								if aid > 10000:
									cflag = len(self.text.GetValue())
								self.text.AppendText("@move(type: BL_MOB, ID: "+str(aid)+", speed: "+str(speed)+", option: "+str(hex(option))+", class: "+str(view)+", pos: (\"" +m+ "\","+str(x)+","+str(y)+"), name\""+ s +"\")\n")
								mobdata[p][aid] = [m,x,y,to_x,to_y,s,view,speed,0,0,0]
								if cflag > 0:
									self.text.SetStyle(cflag, len(self.text.GetValue()), wx.TextAttr("red", "blue"))
						else:
							self.text.AppendText("@move(type: BL_MOB, ID: "+str(aid)+", speed: "+str(speed)+", option: "+str(hex(option))+", class: "+str(view)+", pos: (\"" +m+ "\","+str(x)+","+str(y)+"), name\""+ s +"\")\n")
							mobdata[p] = { aid: [m,x,y,to_x,to_y,s,view,speed,0,0,0] }
					elif type == 6:
						if p in npcdata.keys():
							if aid in npcdata[p].keys():
								pass
							else:
								self.text.AppendText(m+","+ str(x) + ","+ str(y) +",0\tscript\t"+ s +"\t"+ str(view) +",{/* "+ str(aid) +" "+opt+"*/}\n")
								npcdata[p][aid] = [m,x,y,0,s,view,option]
						else:
							self.text.AppendText(m+","+ str(x) + ","+ str(y) +",0\tscript\t"+ s +"\t"+ str(view) +",{/* "+ str(aid) +" "+opt+"*/}\n")
							npcdata[p] = { aid: [m,x,y,0,s,view,option] }
					elif type == 12:
						if p in npcdata.keys():
							if aid in npcdata[p].keys():
								if self.scripttimer.IsChecked() == 1:
									self.text.AppendText('/* ' + str(datetime.now().time()) + ' */\t')
								self.text.AppendText("npcwalkto {},{},\"{}\";\t// {}: speed:{}\n".format(to_x,to_y,s,aid,speed))
							else:
								self.text.AppendText("@move(type: BL_WALKNPC, ID: "+str(aid)+", speed: "+str(speed)+", option: "+str(hex(option))+", class: "+str(view)+", pos: (\"" +m+ "\","+str(x)+","+str(y)+" to:"+str(to_x)+","+str(to_y)+"), name\""+ s +"\")\n")
								npcdata[p][aid] = [m,x,y,0,s,view,option]
						else:
							self.text.AppendText("@move(type: BL_WALKNPC, ID: "+str(aid)+", speed: "+str(speed)+", option: "+str(hex(option))+", class: "+str(view)+", pos: (\"" +m+ "\","+str(x)+","+str(y)+" to:"+str(to_x)+","+str(to_y)+"), name\""+ s +"\")\n")
							npcdata[p] = { aid: [m,x,y,0,s,view,option] }
		elif num == 0x0b4:	#mes
			s = fd[8*2:p_len*2-2]
			s = binascii.unhexlify(s.encode('utf-8')).decode('cp932','ignore')
			if chrdata['name'] != 'unknown name':
				s = s.replace(chrdata['name'],"\"+strcharinfo(0)+\"")
			if self.scripttimer.IsChecked() == 1:
				self.text.AppendText('/* ' + str(datetime.now().time()) + ' */\t')
			self.text.AppendText("mes \""+ s + "\";\n")
		elif num == 0x972:	#mes
			type	= RFIFOB(fd,8)
			s = fd[8*2:p_len*2-2]
			s = binascii.unhexlify(s.encode('utf-8')).decode('cp932','ignore')
			if chrdata['name'] != 'unknown name':
				s = s.replace(chrdata['name'],"\"+strcharinfo(0)+\"")
			if self.scripttimer.IsChecked() == 1:
				self.text.AppendText('/* ' + str(datetime.now().time()) + ' */\t')
			self.text.AppendText("mes \"{}\";\t//type:{}\n".format(s,type))
		elif num == 0x0b5:	#next
			if self.scripttimer.IsChecked() == 1:
				self.text.AppendText('/* ' + str(datetime.now().time()) + ' */\t')
			self.text.AppendText("next;\n")
		elif num == 0x973:	#next
			type	= RFIFOB(fd,6)
			if self.scripttimer.IsChecked() == 1:
				self.text.AppendText('/* ' + str(datetime.now().time()) + ' */\t')
			self.text.AppendText("next;\t//type:{}\n".format(type))
		elif num == 0x0b6:	#close
			if self.scripttimer.IsChecked() == 1:
				self.text.AppendText('/* ' + str(datetime.now().time()) + ' */\t')
			self.text.AppendText("close;\n")
		elif num == 0x8d6:	#clear
			if self.scripttimer.IsChecked() == 1:
				self.text.AppendText('/* ' + str(datetime.now().time()) + ' */\t')
			self.text.AppendText("clear;\n")
		elif num == 0x0b7:	#select
			s = fd[8*2:p_len*2-4]
			s = binascii.unhexlify(s.encode('utf-8')).decode('cp932','ignore')
			l = s.split(':')
			if chrdata['name'] != 'unknown name':
				s = s.replace(chrdata['name'],"\"+strcharinfo(0)+\"")
			if self.scripttimer.IsChecked() == 1:
				self.text.AppendText('/* ' + str(datetime.now().time()) + ' */\t')
			if len(l) == 1:
				self.text.AppendText("menu \"{}\",-;\n".format(s))
			elif len(l) == 2:
				self.text.AppendText("if(select(\""+s.replace(':','\",\"')+"\") == 2) {\n")
			else:
				self.text.AppendText("switch(select(\""+s.replace(':','\",\"')+"\")) {\n")
		elif num == 0x142:	#input num
			if self.scripttimer.IsChecked() == 1:
				self.text.AppendText('/* ' + str(datetime.now().time()) + ' */\t')
			self.text.AppendText("input '@num;\n")
		elif num == 0x1d4:	#input str
			if self.scripttimer.IsChecked() == 1:
				self.text.AppendText('/* ' + str(datetime.now().time()) + ' */\t')
			self.text.AppendText("input '@str$;\n")
		elif num == 0x1b3:	#cutin
			s = fd[2*2:p_len*2-4]
			s = binascii.unhexlify(s.encode('utf-8')).decode('cp932','ignore')
			s = s.replace("\0","")
			type	= RFIFOB(fd,66)
			if self.scripttimer.IsChecked() == 1:
				self.text.AppendText('/* ' + str(datetime.now().time()) + ' */\t')
			self.text.AppendText("cutin \""+s+"\", "+str(type)+";\n")
		elif num == 0x1b0:	#classchange
			aid		= RFIFOL(fd,2)
			type	= RFIFOB(fd,6)
			class_	= RFIFOL(fd,7)
			p		= self.mapport.GetValue()
			if p in npcdata.keys():
				if aid in npcdata[p].keys():
					if self.scripttimer.IsChecked() == 1:
						self.text.AppendText('/* ' + str(datetime.now().time()) + ' */\t')
					self.text.AppendText("setnpcdisplay \"{}\",{};\t// {}\n".format(npcdata[p][aid][NPC.NAME], class_, aid))
					npcdata[p][aid][NPC.CLASS] = class_
			elif p in mobdata.keys():
				if aid in mobdata[p].keys():
					if self.scripttimer.IsChecked() == 1:
						self.text.AppendText('/* ' + str(datetime.now().time()) + ' */\t')
					self.text.AppendText("@classchange(src: \"{}\"({}), class: {}, type: {})\n".format(mobdata[p][aid][MOB.NAME],aid,class_,type))
		elif num == 0x2b3 or num == 0x9f9 or num == 0xb0c:	#quest_add
			quest_id = RFIFOL(fd,2)
			state	 = RFIFOB(fd,6)
			if self.scripttimer.IsChecked() == 1:
				self.text.AppendText('/* ' + str(datetime.now().time()) + ' */\t')
			self.text.AppendText("setquest {};\t// state={}\n".format(quest_id, state))
		elif num == 0x2b4:	#quest_del
			quest_id = RFIFOL(fd,2)
			if self.scripttimer.IsChecked() == 1:
				self.text.AppendText('/* ' + str(datetime.now().time()) + ' */\t')
			self.text.AppendText("delquest {};\n".format(quest_id))
		elif num == 0x09a:	#broadcast
			color		= RFIFOL(fd,4)
			s = fd[4*2:p_len*2-2]
			s = binascii.unhexlify(s.encode('utf-8')).decode('cp932','ignore')
			if chrdata['name'] != 'unknown name':
				s = s.replace(chrdata['name'],"\"+strcharinfo(0)+\"")
			if self.scripttimer.IsChecked() == 1:
				self.text.AppendText('/* ' + str(datetime.now().time()) + ' */\t')
			if color == 0x65756c62:		#blue
				self.text.AppendText("announce {}, 0x10;\n".format(s))
			elif color == 0x73737373:	#ssss -> WoE
				self.text.AppendText("announce {}, 0x20;\n".format(s))
			elif color == 0x6c6f6f74:	#tool
				self.text.AppendText("announce {}, 0x30;\n".format(s))
			elif color == 0:
				self.text.AppendText("announce {}, 0;\n".format(s))
			else:
				color = format(color, '#06x')
				self.text.AppendText("@broadcast(mes: {}, type: {})\n".format(s, color))
		elif num == 0x1c3 or num == 0x40c:	#announce
			color		= RFIFOL(fd,4)
			fontType	= RFIFOW(fd,8)
			fontSize	= RFIFOW(fd,10)
			fontAlign	= RFIFOW(fd,12)
			fontY		= RFIFOW(fd,14)
			s = fd[16*2:p_len*2-2]
			s = binascii.unhexlify(s.encode('utf-8')).decode('cp932','ignore')
			if chrdata['name'] != 'unknown name':
				s = s.replace(chrdata['name'],"\"+strcharinfo(0)+\"")
			color = format(color, '#08x')
			if self.scripttimer.IsChecked() == 1:
				self.text.AppendText('/* ' + str(datetime.now().time()) + ' */\t')
			if fontType == 400 and fontSize == 12 and fontAlign == 0 and fontY == 0:
				self.text.AppendText("announce \"{}\", 0x9, {};\n".format(s, color))
			else:
				fontType = format(fontType, '#06x')
				self.text.AppendText("announce \"{}\", 0x9, {}, {}, {}, {}, {};\n".format(s, color, fontType, fontSize, fontAlign, fontY))
		elif num == 0x2f0:	#progressbar
			color		= RFIFOL(fd,2)
			casttime	= RFIFOL(fd,6)
			color = format(color, '#08x')
			if self.scripttimer.IsChecked() == 1:
				self.text.AppendText('/* ' + str(datetime.now().time()) + ' */\t')
			self.text.AppendText("progressbar {};\t//color={}\n".format(casttime,color))
		elif num == 0x9d1:	#progressbar_unit
			aid			= RFIFOL(fd,2)
			color		= RFIFOL(fd,6)
			casttime	= RFIFOL(fd,10)
			color = format(color, '#08x')
			p		= self.mapport.GetValue()
			if p in npcdata.keys():
				if aid in npcdata[p].keys():
					if self.scripttimer.IsChecked() == 1:
						self.text.AppendText('/* ' + str(datetime.now().time()) + ' */\t')
					self.text.AppendText("progressbar {},\"{}\";\t//color={}\n".format(casttime,npcdata[p][aid][NPC.NAME],color))
				else:
					self.text.AppendText("progressbar {};\t//color={}, aid={}\n".format(casttime,color,aid))
		elif num == 0x1ff:	#blown
			aid	= RFIFOL(fd,2)
			x	= RFIFOW(fd,6)
			y	= RFIFOW(fd,8)
			dx	= x - chrdata['x']
			dy	= y - chrdata['y']
			dir	= 1*(dx>0  and dy<0) \
				+ 2*(dx>0  and dy==0) \
				+ 3*(dx>0  and dy>0) \
				+ 4*(dx==0 and dy>0) \
				+ 5*(dx<0  and dy>0) \
				+ 6*(dx<0  and dy==0) \
				+ 7*(dx<0  and dy<0)
			dist = abs(dx) if abs(dx) > abs(dy) else abs(dy)
			if self.hiddenbattle.IsChecked() == 1:
				pass
			elif chrdata['aid'] == aid:
				chrdata['x'] = x
				chrdata['y'] = y
				self.statusbar.SetStatusText(chrdata['mapname']+':('+str(chrdata['x'])+', '+str(chrdata['y'])+")", 0)
				if p_len*2+2 < len(self.buf):
					next_num = RFIFOW(self.buf,10)
					if next_num == 0x11a or next_num == 0x9cb:
						skillid	= RFIFOW(self.buf,12)
						if skillid == 5023:
							pass
						else:
							if self.scripttimer.IsChecked() == 1:
								self.text.AppendText('/* ' + str(datetime.now().time()) + ' */\t')
							self.text.AppendText("pushpc {}, {};\n".format(dir, dist))
					else:
						if self.scripttimer.IsChecked() == 1:
							self.text.AppendText('/* ' + str(datetime.now().time()) + ' */\t')
						self.text.AppendText("pushpc {}, {};\n".format(dir, dist))
				else:
					if self.scripttimer.IsChecked() == 1:
						self.text.AppendText('/* ' + str(datetime.now().time()) + ' */\t')
					self.text.AppendText("pushpc {}, {};\n".format(dir, dist))
		elif num == 0x08a:	#nomalattack
			type	= RFIFOB(fd,26)
			if self.hiddenbattle.IsChecked() == 1:
				pass
			elif type == 1 or type == 2 or type == 3:	#pickup/sitdown/standup motion
				pass
			else:
				aid		= RFIFOL(fd,2)
				dst		= RFIFOL(fd,6)
				tick	= RFIFOL(fd,10)
				sdelay	= RFIFOL(fd,14)
				ddelay	= RFIFOL(fd,18)
				damage	= RFIFOW(fd,22)
				p		= self.mapport.GetValue()
				if chrdata['aid'] == aid:
					self.text.AppendText("@nomalattack_lower(dst: ({}), damage: {}, sDelay: {}, dDelay: {}, tick: {})\t// self\n".format(dst,damage,sdelay,ddelay,tick))
				elif p in mobdata.keys():
					if aid in mobdata[p].keys():
						if mobdata[p][aid][MOB.TICK] > 0:
							prev = tick
							tick = tick - mobdata[p][aid][MOB.TICK]
							mobdata[p][aid][MOB.TICK] = prev
						else:
							mobdata[p][aid][MOB.TICK] = tick
						if mobdata[p][aid][MOB.POS2X] > 0:
							mobdata[p][aid][MOB.POS2X] = 0
							mobdata[p][aid][MOB.POS2Y] = 0
						self.text.AppendText("@nomalattack_lower(src: {}:\"{}\"({}), dst: ({}), damage: {}, sDelay: {}, dDelay: {}, tick: {})\n".format(mobdata[p][aid][MOB.CLASS],mobdata[p][aid][MOB.NAME],aid,dst,damage,sdelay,ddelay,tick))
		elif num == 0x2e1 or num == 0x8c8:	#nomalattack
			type = RFIFOB(fd,29) if num == 0x8c8 else RFIFOB(fd,28)
			if self.hiddenbattle.IsChecked() == 1:
				pass
			elif type == 1 or type == 2 or type == 3:	#pickup/sitdown/standup motion
				pass
			else:
				aid		= RFIFOL(fd,2)
				dst		= RFIFOL(fd,6)
				tick	= RFIFOL(fd,10)
				sdelay	= RFIFOL(fd,14)
				ddelay	= RFIFOL(fd,18)
				damage	= RFIFOL(fd,22)
				p		= self.mapport.GetValue()
				if chrdata['aid'] == aid:
					if p in mobdata.keys():
						if dst in mobdata[p].keys():
							self.text.AppendText("@nomalattack(dst: {}:\"{}\"({}), damage: {}, sDelay: {}, dDelay: {}, tick: {})\t// self\n".format(mobdata[p][dst][MOB.CLASS],mobdata[p][dst][MOB.NAME],dst,damage,sdelay,ddelay,tick))
					else:
						self.text.AppendText("@nomalattack(dst: ({}), damage: {}, sDelay: {}, dDelay: {}, tick: {})\t// self\n".format(dst,damage,sdelay,ddelay,tick))
				elif p in mobdata.keys():
					if aid in mobdata[p].keys():
						if mobdata[p][aid][MOB.TICK] > 0:
							prev = tick
							tick = tick - mobdata[p][aid][MOB.TICK]
							mobdata[p][aid][MOB.TICK] = prev
						else:
							mobdata[p][aid][MOB.TICK] = tick
						if mobdata[p][aid][MOB.POS2X] > 0:
							mobdata[p][aid][MOB.POS2X] = 0
							mobdata[p][aid][MOB.POS2Y] = 0
						self.text.AppendText("@nomalattack(src: {}:\"{}\"({}), dst: ({}), damage: {}, sDelay: {}, dDelay: {}, tick: {})\n".format(mobdata[p][aid][MOB.CLASS],mobdata[p][aid][MOB.NAME],aid,dst,damage,sdelay,ddelay,tick))
		elif num == 0x13e or num == 0x7fb:	#skill_casting
			aid		= RFIFOL(fd,2)
			dst		= RFIFOL(fd,6)
			skillid	= RFIFOW(fd,14)
			tick	= RFIFOL(fd,20)
			p		= self.mapport.GetValue()
			if self.hiddenbattle.IsChecked() == 1:
				pass
			elif p in mobdata.keys():
				if aid in mobdata[p].keys():
					if self.scripttimer.IsChecked() == 1:
						self.text.AppendText('/* ' + str(datetime.now().time()) + ' */\t')
					self.text.AppendText("@skillcasting(src: {}:\"{}\"({}), dst: {}, skill: \"{}\"({}), casttime: {})\n".format(mobdata[p][aid][MOB.CLASS],mobdata[p][aid][MOB.NAME], aid, dst, getskill(skillid), skillid, tick))
					target = "target"
					if aid == dst:
						target = "self"
					elif dst in mobdata[p].keys():
						target = "friend"
					mode = 0
					if mobdata[p][aid][MOB.POS2X] > 0:
						mode |= 0x2
					elif mobdata[p][aid][MOB.POS2X] == 0:
						mode |= 0x1
					#Table class { skillid { (int)MinRecasttime, LastCasttick, (int)Casttime, (bool)NowCasting, (bool)CastCancel, skilllv, div, val } }
					if mobdata[p][aid][MOB.CLASS] in mobskill.keys():
						if skillid in mobskill[mobdata[p][aid][MOB.CLASS]].keys():
							#LastCasttickが入ってれば現時刻との差分をMinRecasttimeとしてとる
							if mobskill[mobdata[p][aid][MOB.CLASS]][skillid][1] > 0:
								#MinRecasttimeが0か、より短くなるので更新
								if mobskill[mobdata[p][aid][MOB.CLASS]][skillid][0] == 0 or mobskill[mobdata[p][aid][MOB.CLASS]][skillid][0] > gettick() - mobskill[mobdata[p][aid][MOB.CLASS]][skillid][1]:
									mobskill[mobdata[p][aid][MOB.CLASS]][skillid][0] = gettick() - mobskill[mobdata[p][aid][MOB.CLASS]][skillid][1]
							#NowCastingフラグを立てLastCasttickに時刻をいれ、Casttimeを格納する
							mobskill[mobdata[p][aid][MOB.CLASS]][skillid][1] = gettick()
							mobskill[mobdata[p][aid][MOB.CLASS]][skillid][2] = tick
							mobskill[mobdata[p][aid][MOB.CLASS]][skillid][3] = 1
							#すでにmodeが入ってるかもしれないけど更新
							mobskill[mobdata[p][aid][MOB.CLASS]][skillid][10] = mode
						else:
							mobskill[mobdata[p][aid][MOB.CLASS]][skillid] = [0,gettick(),tick,1,0,0,0,0,target,mobdata[p][aid][MOB.NAME],mode]
					else:
						mobskill[mobdata[p][aid][MOB.CLASS]] = { skillid: [0,gettick(),tick,1,0,0,0,0,target,mobdata[p][aid][MOB.NAME],mode] }
		elif num == 0x1b9:	#skill_castcancel
			aid		= RFIFOL(fd,2)
			p		= self.mapport.GetValue()
			if self.hiddenbattle.IsChecked() == 1:
				pass
			elif p in mobdata.keys():
				if aid in mobdata[p].keys():
					if mobdata[p][aid][MOB.CLASS] in mobskill.keys():
						for skillid in mobskill[mobdata[p][aid][MOB.CLASS]].keys():
							#NowCastingが1のスキルをキャンセルOKにする
							if mobskill[mobdata[p][aid][MOB.CLASS]][skillid][3] == 1:
								mobskill[mobdata[p][aid][MOB.CLASS]][skillid][3] = 0
								mobskill[mobdata[p][aid][MOB.CLASS]][skillid][4] = 1
					self.text.AppendText("@skill_castcancel(src: {}:\"{}\"({}))\n".format(mobdata[p][aid][MOB.CLASS],mobdata[p][aid][MOB.NAME],aid))
		elif num == 0x1de:	#skill_damage
			skillid	= RFIFOW(fd,2)
			aid		= RFIFOL(fd,4)
			dst		= RFIFOL(fd,8)
			tick	= RFIFOL(fd,12)
			sdelay	= RFIFOL(fd,16)
			ddelay	= RFIFOL(fd,20)
			damage	= RFIFOL(fd,24)
			skilllv	= RFIFOW(fd,28)
			div_	= RFIFOW(fd,30)
			hit_	= RFIFOB(fd,32)
			p		= self.mapport.GetValue()
			if self.hiddenbattle.IsChecked() == 1:
				pass
			elif p in mobdata.keys():
				if aid in mobdata[p].keys():
					if self.scripttimer.IsChecked() == 1:
						self.text.AppendText('/* ' + str(datetime.now().time()) + ' */\t')
					self.text.AppendText("@skillattack(src: {}:\"{}\"({}), dst: ({}), skill: \"{}\"({}), skill_lv: {}, damage: {}, sDelay: {}, dDelay: {}, div: {}, hit: {}, tick: {})\n".format(mobdata[p][aid][MOB.CLASS],mobdata[p][aid][MOB.NAME],aid,dst,getskill(skillid),skillid,skilllv,damage,sdelay,ddelay,div_,hit_,tick))
					#Table class { skillid { (int)MinRecasttime, LastCasttick, (int)Casttime, (bool)NowCasting, (bool)CastCancel, skilllv, div, val } }
					target = "target"
					if aid == dst:
						target = "self"
					elif dst in mobdata[p].keys():
						target = "friend"
					mode = 0
					if mobdata[p][aid][MOB.POS2X] > 0:
						mode |= 0x2
					elif mobdata[p][aid][MOB.POS2X] == 0:
						mode |= 0x1
					if mobdata[p][aid][MOB.CLASS] in mobskill.keys():
						if skillid in mobskill[mobdata[p][aid][MOB.CLASS]].keys():
							#NowCastingが立ってたら詠唱付スキル
							if mobskill[mobdata[p][aid][MOB.CLASS]][skillid][3] == 1:
								#詠唱付スキルはLastCasttick計算しない
								mobskill[mobdata[p][aid][MOB.CLASS]][skillid][3] = 0
							else:
								#LastCasttickが入ってれば現時刻との差分をMinRecasttimeとしてとる
								if mobskill[mobdata[p][aid][MOB.CLASS]][skillid][1] > 0:
									#MinRecasttimeが0か、より短くなるので更新
									if mobskill[mobdata[p][aid][MOB.CLASS]][skillid][0] == 0 or mobskill[mobdata[p][aid][MOB.CLASS]][skillid][0] > gettick() - mobskill[mobdata[p][aid][MOB.CLASS]][skillid][1]:
										mobskill[mobdata[p][aid][MOB.CLASS]][skillid][0] = gettick() - mobskill[mobdata[p][aid][MOB.CLASS]][skillid][1]
								#LastCasttickに時刻をいれ、データ各種格納
								mobskill[mobdata[p][aid][MOB.CLASS]][skillid][1] = gettick()
								mobskill[mobdata[p][aid][MOB.CLASS]][skillid][5] = skilllv
								mobskill[mobdata[p][aid][MOB.CLASS]][skillid][6] = div_
								#すでにmodeが入ってるかもしれないけど更新
								mobskill[mobdata[p][aid][MOB.CLASS]][skillid][10] = mode
						else:
							mobskill[mobdata[p][aid][MOB.CLASS]][skillid] = [0,gettick(),0,0,0,skilllv,div_,0,target,mobdata[p][aid][MOB.NAME],mode]
					else:
						mobskill[mobdata[p][aid][MOB.CLASS]] = { skillid: [0,gettick(),0,0,0,skilllv,div_,0,target,mobdata[p][aid][MOB.NAME],mode] }
			elif p in npcdata.keys():
				if aid in npcdata[p].keys():
					if self.scripttimer.IsChecked() == 1:
						self.text.AppendText('/* ' + str(datetime.now().time()) + ' */\t')
					self.text.AppendText("@skillattack_effect(src: \"{}\"({}), dst: ({}), skill: \"{}\"({}), skill_lv: {}, damage: {}, sDelay: {}, dDelay: {}, div: {}, hit: {}, tick: {})\n".format(npcdata[p][aid][NPC.NAME],aid,dst,getskill(skillid),skillid,skilllv,damage,sdelay,ddelay,div_,hit_,tick))
		elif num == 0x11a:	#skill_nodamage
			skillid	= RFIFOW(fd,2)
			val		= RFIFOW(fd,4)
			dst		= RFIFOL(fd,6)
			aid		= RFIFOL(fd,10)
			p		= self.mapport.GetValue()
			if self.hiddenbattle.IsChecked() == 1:
				pass
			elif p in mobdata.keys():
				if aid in mobdata[p].keys():
					if self.scripttimer.IsChecked() == 1:
						self.text.AppendText('/* ' + str(datetime.now().time()) + ' */\t')
					self.text.AppendText("@skillnodamage(src: {}:\"{}\"({}), dst: ({}), skill: \"{}\"({}), val: {})\n".format(mobdata[p][aid][MOB.CLASS],mobdata[p][aid][MOB.NAME], aid, dst, getskill(skillid), skillid, val))
					target = "target"
					if aid == dst:
						target = "self"
					elif dst in mobdata[p].keys():
						target = "friend"
					mode = 0
					if mobdata[p][aid][MOB.POS2X] > 0:
						mode |= 0x2
					elif mobdata[p][aid][MOB.POS2X] == 0:
						mode |= 0x1
					#Table class { skillid { (int)MinRecasttime, LastCasttick, (int)Casttime, (bool)NowCasting, (bool)CastCancel, skilllv, div, val } }
					if mobdata[p][aid][MOB.CLASS] in mobskill.keys():
						if skillid in mobskill[mobdata[p][aid][MOB.CLASS]].keys():
							#NowCastingが立ってたら詠唱付スキル
							if mobskill[mobdata[p][aid][MOB.CLASS]][skillid][3] == 1:
								#詠唱付スキルはLastCasttick計算しない
								mobskill[mobdata[p][aid][MOB.CLASS]][skillid][3] = 0
							else:
								#LastCasttickが入ってれば現時刻との差分をMinRecasttimeとしてとる
								if mobskill[mobdata[p][aid][MOB.CLASS]][skillid][1] > 0:
									#MinRecasttimeが0か、より短くなるので更新
									if mobskill[mobdata[p][aid][MOB.CLASS]][skillid][0] == 0 or mobskill[mobdata[p][aid][MOB.CLASS]][skillid][0] > gettick() - mobskill[mobdata[p][aid][MOB.CLASS]][skillid][1]:
										mobskill[mobdata[p][aid][MOB.CLASS]][skillid][0] = gettick() - mobskill[mobdata[p][aid][MOB.CLASS]][skillid][1]
								#LastCasttickに時刻をいれ、データ各種格納
								mobskill[mobdata[p][aid][MOB.CLASS]][skillid][1] = gettick()
								mobskill[mobdata[p][aid][MOB.CLASS]][skillid][7] = val
							#すでにmodeが入ってるかもしれないけど更新
							mobskill[mobdata[p][aid][MOB.CLASS]][skillid][10] = mode
						else:
							mobskill[mobdata[p][aid][MOB.CLASS]][skillid] = [0,gettick(),0,0,0,0,0,val,target,mobdata[p][aid][MOB.NAME],mode]
					else:
						mobskill[mobdata[p][aid][MOB.CLASS]] = { skillid: [0,gettick(),0,0,0,0,0,val,target,mobdata[p][aid][MOB.NAME],mode] }
			elif p in npcdata.keys():
				if aid in npcdata[p].keys():
					if self.scripttimer.IsChecked() == 1:
						self.text.AppendText('/* ' + str(datetime.now().time()) + ' */\t')
					self.text.AppendText("@skillnodamage_effect(src: \"{}\"({}), dst: ({}), skill: \"{}\"({}), val: {})\n".format(npcdata[p][aid][NPC.NAME],aid,dst,getskill(skillid),skillid,val))
		elif num == 0x9cb:	#skill_nodamage
			skillid	= RFIFOW(fd,2)
			val		= RFIFOL(fd,4)
			dst		= RFIFOL(fd,8)
			aid		= RFIFOL(fd,12)
			p		= self.mapport.GetValue()
			if self.hiddenbattle.IsChecked() == 1:
				pass
			if aid == 0:
				pass
			elif p in mobdata.keys():
				if aid in mobdata[p].keys():
					if self.scripttimer.IsChecked() == 1:
						self.text.AppendText('/* ' + str(datetime.now().time()) + ' */\t')
					self.text.AppendText("@skillnodamage(src: {}:\"{}\"({}), dst: ({}), skill: \"{}\"({}), val: {})\n".format(mobdata[p][aid][MOB.CLASS],mobdata[p][aid][MOB.NAME], aid, dst, getskill(skillid), skillid, val))
					target = "target"
					if aid == dst:
						target = "self"
					elif dst in mobdata[p].keys():
						target = "friend"
					mode = 0
					if mobdata[p][aid][MOB.POS2X] > 0:
						mode |= 0x2
					elif mobdata[p][aid][MOB.POS2X] == 0:
						mode |= 0x1
					#Table class { skillid { (int)MinRecasttime, LastCasttick, (int)Casttime, (bool)NowCasting, (bool)CastCancel, skilllv, div, val } }
					if mobdata[p][aid][MOB.CLASS] in mobskill.keys():
						if skillid in mobskill[mobdata[p][aid][MOB.CLASS]].keys():
							#NowCastingが立ってたら詠唱付スキル
							if mobskill[mobdata[p][aid][MOB.CLASS]][skillid][3] == 1:
								#詠唱付スキルはLastCasttick計算しない
								mobskill[mobdata[p][aid][MOB.CLASS]][skillid][3] = 0
							else:
								#LastCasttickが入ってれば現時刻との差分をMinRecasttimeとしてとる
								if mobskill[mobdata[p][aid][MOB.CLASS]][skillid][1] > 0:
									#MinRecasttimeが0か、より短くなるので更新
									if mobskill[mobdata[p][aid][MOB.CLASS]][skillid][0] == 0 or mobskill[mobdata[p][aid][MOB.CLASS]][skillid][0] > gettick() - mobskill[mobdata[p][aid][MOB.CLASS]][skillid][1]:
										mobskill[mobdata[p][aid][MOB.CLASS]][skillid][0] = gettick() - mobskill[mobdata[p][aid][MOB.CLASS]][skillid][1]
								#LastCasttickに時刻をいれ、データ各種格納
								mobskill[mobdata[p][aid][MOB.CLASS]][skillid][1] = gettick()
								mobskill[mobdata[p][aid][MOB.CLASS]][skillid][7] = val
							#すでにmodeが入ってるかもしれないけど更新
							mobskill[mobdata[p][aid][MOB.CLASS]][skillid][10] = mode
						else:
							mobskill[mobdata[p][aid][MOB.CLASS]][skillid] = [0,gettick(),0,0,0,0,0,val,target,mobdata[p][aid][MOB.NAME],mode]
					else:
						mobskill[mobdata[p][aid][MOB.CLASS]] = { skillid: [0,gettick(),0,0,0,0,0,val,target,mobdata[p][aid][MOB.NAME],mode] }
			elif p in npcdata.keys():
				if aid in npcdata[p].keys():
					if self.scripttimer.IsChecked() == 1:
						self.text.AppendText('/* ' + str(datetime.now().time()) + ' */\t')
					self.text.AppendText("@skillnodamage_effect(src: \"{}\"({}), dst: ({}), skill: \"{}\"({}), val: {})\n".format(npcdata[p][aid][NPC.NAME],aid,dst,getskill(skillid),skillid,val))
		elif num == 0x117:	#skill_poseffect
			skillid	= RFIFOW(fd,2)
			aid		= RFIFOL(fd,4)
			val		= RFIFOW(fd,8)
			x		= RFIFOW(fd,10)
			y		= RFIFOW(fd,12)
			tick	= RFIFOL(fd,14)
			p		= self.mapport.GetValue()
			if self.hiddenbattle.IsChecked() == 1:
				pass
			elif p in mobdata.keys():
				if aid in mobdata[p].keys():
					if self.scripttimer.IsChecked() == 1:
						self.text.AppendText('/* ' + str(datetime.now().time()) + ' */\t')
					self.text.AppendText("@skillposeffect(src: {}:\"{}\"({}), skill: \"{}\"({}), val: {}, pos({}, {}), tick: {})\n".format(mobdata[p][aid][MOB.CLASS],mobdata[p][aid][MOB.NAME], aid, getskill(skillid), skillid, val, x, y, tick))
					target = "around"
					#現在地か行き先が詠唱先と同じなら
					if (mobdata[p][aid][MOB.POSX] == x and mobdata[p][aid][MOB.POSY] == y) or (mobdata[p][aid][MOB.POS2X] == x and mobdata[p][aid][MOB.POS2Y] == y):
						target = "self"
					mode = 0
					if mobdata[p][aid][MOB.POS2X] > 0:
						mode |= 0x2
					elif mobdata[p][aid][MOB.POS2X] == 0:
						mode |= 0x1
					#Table class { skillid { (int)MinRecasttime, LastCasttick, (int)Casttime, (bool)NowCasting, (bool)CastCancel, skilllv, div, val } }
					if mobdata[p][aid][MOB.CLASS] in mobskill.keys():
						if skillid in mobskill[mobdata[p][aid][MOB.CLASS]].keys():
							#NowCastingが立ってたら詠唱付スキル
							if mobskill[mobdata[p][aid][MOB.CLASS]][skillid][3] == 1:
								#詠唱付スキルはLastCasttick計算しない
								mobskill[mobdata[p][aid][MOB.CLASS]][skillid][3] = 0
							else:
								#LastCasttickが入ってれば現時刻との差分をMinRecasttimeとしてとる
								if mobskill[mobdata[p][aid][MOB.CLASS]][skillid][1] > 0:
									#MinRecasttimeが0か、より短くなるので更新
									if mobskill[mobdata[p][aid][MOB.CLASS]][skillid][0] == 0 or mobskill[mobdata[p][aid][MOB.CLASS]][skillid][0] > gettick() - mobskill[mobdata[p][aid][MOB.CLASS]][skillid][1]:
										mobskill[mobdata[p][aid][MOB.CLASS]][skillid][0] = gettick() - mobskill[mobdata[p][aid][MOB.CLASS]][skillid][1]
								#LastCasttickに時刻をいれ、データ各種格納
								mobskill[mobdata[p][aid][MOB.CLASS]][skillid][1] = gettick()
								#mobskill[mobdata[p][aid][MOB.CLASS]][skillid][7] = val
							#すでにmodeが入ってるかもしれないけど更新
							mobskill[mobdata[p][aid][MOB.CLASS]][skillid][10] = mode
						else:
							mobskill[mobdata[p][aid][MOB.CLASS]][skillid] = [0,gettick(),0,0,0,0,0,0,target,mobdata[p][aid][MOB.NAME],mode]
					else:
						mobskill[mobdata[p][aid][MOB.CLASS]] = { skillid: [0,gettick(),0,0,0,0,0,0,target,mobdata[p][aid][MOB.NAME],mode] }
			elif p in npcdata.keys():
				if aid in npcdata[p].keys():
					if self.scripttimer.IsChecked() == 1:
						self.text.AppendText('/* ' + str(datetime.now().time()) + ' */\t')
					self.text.AppendText("@skillposeffect_effect(src: \"{}\"({}), skill: \"{}\"({}), val: {}, pos({}, {}), tick: {})\n".format(npcdata[p][aid][NPC.NAME], aid, getskill(skillid), skillid, val, x, y, tick))
		elif num == 0x9ca:	#skill_unit
			aid		= RFIFOL(fd,8)
			x		= RFIFOW(fd,12)
			y		= RFIFOW(fd,14)
			unit_id	= RFIFOL(fd,16)
			skilllv	= RFIFOB(fd,22)
			p		= self.mapport.GetValue()
			if self.hiddenbattle.IsChecked() == 1:
				pass
			elif p in mobdata.keys():
				if aid in mobdata[p].keys():
					if self.scripttimer.IsChecked() == 1:
						self.text.AppendText('/* ' + str(datetime.now().time()) + ' */\t')
					self.text.AppendText("@skillunit_appeared(\"{}\"({}), pos({}, {}), unit_id: {}({}), skill_lv: {})\n".format(mobdata[p][aid][MOB.NAME], aid, x, y, getunitid(unit_id), hex(unit_id), skilllv))
		elif num == 0xa41:	#warningplean
			aid		= RFIFOL(fd,2)
			skillid	= RFIFOW(fd,6)
			skilllv	= RFIFOW(fd,8)
			x		= RFIFOW(fd,10)
			y		= RFIFOW(fd,12)
			p		= self.mapport.GetValue()
			if self.hiddenbattle.IsChecked() == 1:
				pass
			elif p in mobdata.keys():
				if aid in mobdata[p].keys():
					if self.scripttimer.IsChecked() == 1:
						self.text.AppendText('/* ' + str(datetime.now().time()) + ' */\t')
					self.text.AppendText("@skill_warningplean(\"{}\"({}), pos({}, {}), skill_id: {}, skill_lv: {})\n".format(mobdata[p][aid][MOB.NAME], aid, x, y, skillid, skilllv))
		elif num == 0x080:	#clear_unit
			aid		= RFIFOL(fd,2)
			type	= RFIFOB(fd,6)
			p		= self.mapport.GetValue()
			if self.hiddenbattle.IsChecked() == 1:
				pass
			elif p in mobdata.keys():
				if aid in mobdata[p].keys():
					if self.scripttimer.IsChecked() == 1:
						self.text.AppendText('/* ' + str(datetime.now().time()) + ' */\t')
					if type != 0:
						self.text.AppendText("@mob_defeated(\"{}\"({}), type: {})\n".format(mobdata[p][aid][MOB.NAME], aid, type))
					if type == 1:
						mobdata[p][aid][MOB.DEADTICK] = gettick()
		elif num == 0xacc:	#gainexp
			exp		= RFIFOQ(fd,6)
			type	= RFIFOW(fd,14)
			quest	= RFIFOW(fd,16)
			if type==1:
				chrdata['BaseExp'] += exp
				self.text.AppendText("getexp "+str(exp)+",0," +str(quest)+ ";\n")
				self.statusbar.SetStatusText('BaseExp: {:>15,}'.format(chrdata['BaseExp']), 1)
			else:
				chrdata['JobExp'] += exp
				self.text.AppendText("getexp 0,"+str(exp)+"," +str(quest)+ ";\n")
				self.statusbar.SetStatusText('JobExp: {:>15,}'.format(chrdata['JobExp']), 2)
		elif num == 0x229:	#changeoption
			aid		= RFIFOL(fd,2)
			opt1	= RFIFOW(fd,6)
			opt2	= RFIFOW(fd,8)
			option	= RFIFOW(fd,10)
			karma	= RFIFOB(fd,14)
			p		= self.mapport.GetValue()
			s		= ""
			if chrdata['aid'] == aid:
				if self.scripttimer.IsChecked() == 1:
					self.text.AppendText('/* ' + str(datetime.now().time()) + ' */\t')
				if opt1 > 0 or opt2 > 0:
					self.text.AppendText("@changeoption opt1: {}, opt2: {}\t// self\n".format(opt1, opt2))
				else:
					self.text.AppendText("@changeoptionend opt1: {}, opt2: {}\t// self\n".format(opt1, opt2))
			elif p in npcdata.keys():
				if aid in npcdata[p].keys():
					if npcdata[p][aid][NPC.OPTION] == 2 or option == 2:
						s += "hideonnpc" if option == 2 else "hideoffnpc"
					elif npcdata[p][aid][NPC.OPTION] == 4 or option == 4:
						s += "cloakonnpc" if option == 4 else "cloakoffnpc"
					else:
						s += "hideoffnpc"
					s += " \""+npcdata[p][aid][NPC.NAME]+"\";\t// "+str(aid)
					npcdata[p][aid][NPC.OPTION] = option
					if self.scripttimer.IsChecked() == 1:
						self.text.AppendText('/* ' + str(datetime.now().time()) + ' */\t')
					self.text.AppendText(s+"\n")
			elif p in mobdata.keys():
				if aid in mobdata[p].keys():
					self.text.AppendText("@changeoption(id: "+str(aid)+", opt1: "+str(opt1)+", opt2: "+str(opt2)+", option: "+str(option)+", karma: "+str(karma)+")\n")
		elif num == 0x0c0:	#emotion
			aid		= RFIFOL(fd,2)
			type	= RFIFOB(fd,6)
			p		= self.mapport.GetValue()
			if chrdata['aid'] == aid:
				if self.scripttimer.IsChecked() == 1:
					self.text.AppendText('/* ' + str(datetime.now().time()) + ' */\t')
				self.text.AppendText("emotion "+str(type)+",\"\";\t// self\n")
			elif p in npcdata.keys():
				if aid in npcdata[p].keys():
					if self.scripttimer.IsChecked() == 1:
						self.text.AppendText('/* ' + str(datetime.now().time()) + ' */\t')
					self.text.AppendText("emotion "+str(type)+",\""+npcdata[p][aid][NPC.NAME]+"\";\t// " +str(aid)+ "\n")
			elif p in mobdata.keys():
				if aid in mobdata[p].keys():
					if self.scripttimer.IsChecked() == 1:
						self.text.AppendText('/* ' + str(datetime.now().time()) + ' */\t')
					if p_len*2+2 < len(self.buf):
						next_num = RFIFOW(self.buf,7)
						if next_num == 0x1de or next_num == 0x11a or next_num == 0x9cb or next_num == 0x117:
							skillid	= RFIFOW(self.buf,9)
							self.text.AppendText("@emotion_skill "+str(type)+",\""+mobdata[p][aid][MOB.NAME]+"\";\t// " +getskill(skillid)+ ":" +str(aid)+ "\n")
					else:
						self.text.AppendText("@emotion "+str(type)+",\""+mobdata[p][aid][MOB.NAME]+"\";\t// " +str(aid)+ "\n")
		elif num == 0x19b or num == 0x1f3:	#misceffect
			aid		= RFIFOL(fd,2)
			type	= RFIFOL(fd,6)
			p		= self.mapport.GetValue()
			if chrdata['aid'] == aid:
				if self.scripttimer.IsChecked() == 1:
					self.text.AppendText('/* ' + str(datetime.now().time()) + ' */\t')
				self.text.AppendText("misceffect "+str(type)+",\"\";\t// self\n")
			elif p in npcdata.keys():
				if aid in npcdata[p].keys():
					if self.scripttimer.IsChecked() == 1:
						self.text.AppendText('/* ' + str(datetime.now().time()) + ' */\t')
					self.text.AppendText("misceffect "+str(type)+",\""+npcdata[p][aid][NPC.NAME]+"\";\t// " +str(aid)+ "\n")
			elif p in mobdata.keys():
				if aid in mobdata[p].keys():
					if self.scripttimer.IsChecked() == 1:
						self.text.AppendText('/* ' + str(datetime.now().time()) + ' */\t')
					self.text.AppendText("@misceffect "+str(type)+",\""+mobdata[p][aid][MOB.NAME]+"\";\t// " +str(aid)+ "\n")
		elif num == 0x284:	#misceffect_value
			aid		= RFIFOL(fd,2)
			type	= RFIFOL(fd,6)
			num		= RFIFOL(fd,10)
			p		= self.mapport.GetValue()
			if chrdata['aid'] == aid:
				if self.scripttimer.IsChecked() == 1:
					self.text.AppendText('/* ' + str(datetime.now().time()) + ' */\t')
				self.text.AppendText("misceffect_value {},{},\"\";\t// self\n".format(type,num))
			elif p in npcdata.keys():
				if aid in npcdata[p].keys():
					if self.scripttimer.IsChecked() == 1:
						self.text.AppendText('/* ' + str(datetime.now().time()) + ' */\t')
					self.text.AppendText("misceffect_value {},{},\"{}\";\t// {}\n".format(type,num,npcdata[p][aid][NPC.NAME],aid))
			elif p in mobdata.keys():
				if aid in mobdata[p].keys():
					if self.scripttimer.IsChecked() == 1:
						self.text.AppendText('/* ' + str(datetime.now().time()) + ' */\t')
					self.text.AppendText("@misceffect_value {},{},\"{}\";\t// {}\n".format(type,num,mobdata[p][aid][MOB.NAME],aid))
		elif num == 0x144:	#viewpoint
			aid		= RFIFOL(fd,2)
			type	= RFIFOL(fd,6)
			x		= RFIFOL(fd,10)
			y		= RFIFOL(fd,14)
			id		= RFIFOB(fd,18)
			color	= RFIFOL(fd,19)
			color	= color&0x00FFFFFF
			if self.scripttimer.IsChecked() == 1:
				self.text.AppendText('/* ' + str(datetime.now().time()) + ' */\t')
			self.text.AppendText("viewpoint "+str(type)+", "+str(x)+", "+str(y)+", "+str(id)+", 0x"+format(color, '06X')+";\t// "+str(aid)+"\n")
		elif num == 0x0d7:	#chatwnd
			p = self.mapport.GetValue()
			if p in npcdata.keys():
				aid		= RFIFOL(fd,4)
				if aid in npcdata[p].keys():
					s_len	= RFIFOW(fd,2)
					chatid	= RFIFOL(fd,8)
					if chatid in waitingroom.keys():
						pass
					else:
						s = fd[17*2:s_len*2]
						s = binascii.unhexlify(s.encode('utf-8')).decode('cp932','ignore')
						s = s.replace("\0","")
						waitingroom[chatid] = 1
						self.text.AppendText("waitingroom \""+s+"\", 0;\t// " +str(aid)+ "\n")
		elif num == 0x192:	#mapcell
			x		= RFIFOW(fd,2)
			y		= RFIFOW(fd,4)
			type	= RFIFOW(fd,6)
			s = fd[8*2:p_len*2-2]
			s = binascii.unhexlify(s.encode('utf-8')).decode('cp932','ignore')
			s = s.replace("\0","")
			self.text.AppendText("setcell \"{}\", {}, {}, {};\n".format(s, x, y, type))
		elif num == 0x1d3:	#soundeffect
			s = fd[2*2:26*2]
			s = binascii.unhexlify(s.encode('utf-8')).decode('cp932','ignore')
			#s = "" if s[0] == '\0' else s
			s = s[:s.find('\0')]
			type		= RFIFOB(fd,26)
			interval	= RFIFOL(fd,27)
			aid			= RFIFOL(fd,31)
			if self.scripttimer.IsChecked() == 1:
				self.text.AppendText('/* ' + str(datetime.now().time()) + ' */\t')
			self.text.AppendText("soundeffect \""+s+"\", "+str(type)+", "+str(interval)+";\t// "+str(aid)+"\n")
		elif num == 0x7fe:	#musiceffect
			s = fd[2*2:26*2]
			s = binascii.unhexlify(s.encode('utf-8')).decode('cp932','ignore')
			#s = "" if s[0] == '\0' else s
			s = s[:s.find('\0')]
			if self.scripttimer.IsChecked() == 1:
				self.text.AppendText('/* ' + str(datetime.now().time()) + ' */\t')
			self.text.AppendText("musiceffect \""+s+"\";\n")
		elif num == 0xb8c:	#musiceffect
			type		= RFIFOB(fd,4)
			s = fd[5*2:]
			s = binascii.unhexlify(s.encode('utf-8')).decode('cp932','ignore')
			#s = "" if s[0] == '\0' else s
			s = s[:s.find('\0')]
			if self.scripttimer.IsChecked() == 1:
				self.text.AppendText('/* ' + str(datetime.now().time()) + ' */\t')
			self.text.AppendText("musiceffect \"{}\",{};\n".format(s,type))
		elif num == 0x0c4:	#npcshop
			aid	= RFIFOL(fd,2)
			self.tmp_id = aid
		elif num == 0x0c6:	#npcshop2
			i = 0
			s = ""
			while i*13+4 < p_len:
				if i > 0:
					s += ","
				s	+= str(RFIFOL(fd,13+i*13))
				s	+= ":"
				s	+= str(RFIFOL(fd,4+i*13))
				i += 1
			aid = self.tmp_id
			p = self.mapport.GetValue()
			if aid == 0:
				m = chrdata["mapname"]
				self.text.AppendText("-\tshop\t"+ m[:-4] +"#callshop\t-1," +s +"\t// selfpos("+ str(chrdata["x"])+", "+ str(chrdata["y"]) +")\n")
			else:
				if p in npcdata.keys():
					if aid in npcdata[p].keys():
						self.text.AppendText(npcdata[p][aid][NPC.MAP]+","+ str(npcdata[p][aid][NPC.POSX]) + ","+ str(npcdata[p][aid][NPC.POSY]) +","+ str(npcdata[p][aid][NPC.POSD]) +"\tshop\t"+ str(npcdata[p][aid][NPC.NAME]) +"\t"+ str(npcdata[p][aid][NPC.CLASS]) + "," +s +"\t// "+ str(aid) +"\n")
			self.tmp_id = 0
		elif num == 0x0b1:	#updatestatus
			type	= RFIFOW(fd,2)
			value	= RFIFOL(fd,4)
			if type == 20:	#Zeny
				zeny = value - chrdata['Zeny']
				if chrdata['Zeny'] >= 0:
					self.text.AppendText('set Zeny, Zeny {:>+};\n'.format(zeny))
				else:
					self.text.AppendText('@update_status(Zeny: {} ({:=+}))\n'.format(value, zeny))
				chrdata['Zeny'] = value
				self.statusbar.SetStatusText('Zeny: {:>15,}'.format(chrdata['Zeny']), 3)
		elif num == 0xacb:	#updatestatus
			type	= RFIFOW(fd,2)
			value	= RFIFOQ(fd,4)
			if type == 1:	#BaseExp
#				if chrdata['BaseExp'] >= 0:
#					exp = value - chrdata['BaseExp']
#					self.text.AppendText("getexp "+str(exp)+",0;\t// "+str(value)+"\n")
#				else:
#					self.text.AppendText("@update_status(BaseExp: "+str(value)+")\n")
				chrdata['BaseExp'] = value
				self.statusbar.SetStatusText('BaseExp: {:>15,}'.format(chrdata['BaseExp']), 1)
			elif type == 2:	#JobExp
#				if chrdata['JobExp'] >= 0:
#					exp = value - chrdata['JobExp']
#					self.text.AppendText("getexp "+str(exp)+",0;\t// "+str(value)+"\n")
#				else:
#					self.text.AppendText("@update_status(JobExp: "+str(value)+")\n")
				chrdata['JobExp'] = value
				self.statusbar.SetStatusText('JobExp: {:>15,}'.format(chrdata['JobExp']), 2)
		elif num == 0x82d:	#charactor_select
			pass
		elif num == 0x9a0:	#charactor_select
			pass
		elif num == 0x99d:	#charactor_select
			c_len	= RFIFOW(fd,2)
			if c_len == 4:
				pass
			else:
				i = 4
				j = 0
				while i < c_len:
					char_num = RFIFOW(fd,122+j*155)
					s = fd[(92+j*155)*2:(92+24+j*155)*2]
					s = binascii.unhexlify(s.encode('utf-8')).decode('cp932','ignore')
					s = s.replace("\0","")
					chrselect[char_num] = {'Char_id': RFIFOL(fd,4+j*155), 'Char_Name': s, 'BaseExp': RFIFOQ(fd,8+j*155), 'Zeny': RFIFOL(fd,16+j*155), 'JobExp': RFIFOQ(fd,20+j*155) }
					self.text.AppendText("[No,{}, ID:{}, Name:\"{}\"]\n".format(char_num, chrselect[char_num]['Char_id'], s))
					i += 155
					j += 1
		elif num == 0xb72:	#charactor_select
			c_len	= RFIFOW(fd,2)
			if c_len == 4:
				pass
			else:
				i = 4
				j = 0
				while i < c_len:
					char_num = RFIFOW(fd,142+j*175)
					s = fd[(112+j*175)*2:(112+24+j*175)*2]
					s = binascii.unhexlify(s.encode('utf-8')).decode('cp932','ignore')
					s = s.replace("\0","")
					chrselect[char_num] = {'Char_id': RFIFOL(fd,4+j*175), 'Char_Name': s, 'BaseExp': RFIFOQ(fd,8+j*175), 'Zeny': RFIFOL(fd,16+j*175), 'JobExp': RFIFOQ(fd,20+j*175) }
					self.text.AppendText("[No,{}, ID:{}, Name:\"{}\"]\n".format(char_num, chrselect[char_num]['Char_id'], s))
					i += 175
					j += 1
		elif num == 0x71:	#charactor_select
			aid	= RFIFOL(fd,2)
			s = fd[2*6:p_len*2-16]
			s = binascii.unhexlify(s.encode('utf-8')).decode('cp932','ignore')
			s = s.replace("\0","")
			port	= RFIFOW(fd,26)
			i = s.find('.gat')
			if i > 0:
				chrdata['mapname'] = s
				self.mapport.SetValue(str(port))
				self.th.setport(int(self.charport.GetValue()), int(self.mapport.GetValue()))
				self.statusbar.SetStatusText(chrdata['mapname']+':('+str(chrdata['x'])+', '+str(chrdata['y'])+")", 0)
				i = 0
				while i < 15:
					if not i in chrselect.keys():
						chrselect[i] = dummy_chr
					elif chrselect[i]['Char_id'] == aid:
						chrdata['BaseExp'] = chrselect[i]['BaseExp']
						self.statusbar.SetStatusText('BaseExp: {:>15,}'.format(chrdata['BaseExp']), 1)
						chrdata['JobExp'] = chrselect[i]['JobExp']
						self.statusbar.SetStatusText('JobExp: {:>15,}'.format(chrdata['JobExp']), 2)
						chrdata['Zeny'] = chrselect[i]['Zeny']
						chrdata['name'] = chrselect[i]['Char_Name']
						self.statusbar.SetStatusText('Zeny: {:>15,}'.format(chrdata['Zeny']), 3)
						self.text.AppendText("No.{} selected.\n".format(i))
					i += 1
		elif num == 0x91:	#changemap
			s = fd[2*2:p_len*2-8]
			s = binascii.unhexlify(s.encode('utf-8')).decode('cp932','ignore')
			s = s.replace("\0","")
			x	= RFIFOW(fd,18)
			y	= RFIFOW(fd,20)
			#if s[-4:] == ".gat":
			i = s.find('.gat')
			if i > 0:
				s = s[:i+4]
				aid = self.CheckNearNPC(chrdata['mapname'], chrdata['x'], chrdata['y']);
				p = self.mapport.GetValue()
				if aid >= 0:
					if p in warpnpc.keys():
						if aid in warpnpc[p].keys():
							self.text.AppendText("@changemap \"{}\", x : {}, y : {};\t// from: {}({}, {})\n".format(s, x, y, chrdata['mapname'], chrdata['x'], chrdata['y']))
						else:
							self.text.AppendText("{},{},{},0\twarp\t{}\t2,2,{},{},{}\t// {} from: {}({}, {})\n".format(
								npcdata[p][aid][NPC.MAP],npcdata[p][aid][NPC.POSX],npcdata[p][aid][NPC.POSY],npcdata[p][aid][NPC.NAME], s, x, y, aid, chrdata['mapname'], chrdata['x'], chrdata['y']))
							warpnpc[p][aid] = npcdata[p][aid][NPC.NAME]
					else:
						self.text.AppendText("{},{},{},0\twarp\t{}\t2,2,{},{},{}\t// {} from: {}({}, {})\n".format(
							npcdata[p][aid][NPC.MAP],npcdata[p][aid][NPC.POSX],npcdata[p][aid][NPC.POSY],npcdata[p][aid][NPC.NAME], s, x, y, aid, chrdata['mapname'], chrdata['x'], chrdata['y']))
						warpnpc[p] = { aid: npcdata[p][aid][NPC.NAME] }
				else:
					if not '@' in s:
						self.text.AppendText("warp \"{}\", {}, {};\t// from: {}({}, {})\n".format(s, x, y, chrdata['mapname'], chrdata['x'], chrdata['y']))
					else:
						self.text.AppendText("warp getmdmapname(\"{}\"), {}, {};\t// from: {}({}, {})\n".format(s, x, y, chrdata['mapname'], chrdata['x'], chrdata['y']))
				chrdata['mapname'] = s
				chrdata['x'] = x
				chrdata['y'] = y
				self.statusbar.SetStatusText(chrdata['mapname']+':('+str(chrdata['x'])+', '+str(chrdata['y'])+")", 0)
			else:
				self.text.AppendText("@changemap Failed packet\n")
		elif num == 0x92:	#changemapserver
			s = fd[2*2:p_len*2-20]
			s = binascii.unhexlify(s.encode('utf-8')).decode('cp932','ignore')
			s = s.replace("\0","")
			x	= RFIFOW(fd,18)
			y	= RFIFOW(fd,20)
			port	= RFIFOW(fd,26)
			#if s[-4:] == ".gat":
			i = s.find('.gat')
			if i > 0:
				s = s[:i+4]
				aid = self.CheckNearNPC(chrdata['mapname'], chrdata['x'], chrdata['y']);
				p = self.mapport.GetValue()
				if aid >= 0:
					if p in warpnpc.keys():
						if aid in warpnpc[p].keys():
							self.text.AppendText("@changemapserver \"{}\", x : {}, y : {}, port : {};\t// from: {}({}, {})\n".format(s, x, y, port, chrdata['mapname'], chrdata['x'], chrdata['y']))
						else:
							self.text.AppendText("{},{},{},0\twarp\t{}\t2,2,{},{},{}\t//{} from: {}({}, {})\n".format(
								npcdata[p][aid][NPC.MAP],npcdata[p][aid][NPC.POSX],npcdata[p][aid][NPC.POSY],npcdata[p][aid][NPC.NAME], s, x, y, aid, chrdata['mapname'], chrdata['x'], chrdata['y']))
							warpnpc[p][aid] = [npcdata[p][aid][NPC.NAME]]
					else:
						self.text.AppendText("{},{},{},0\twarp\t{}\t2,2,{},{},{}\t//{} from: {}({}, {})\n".format(
							npcdata[p][aid][NPC.MAP],npcdata[p][aid][NPC.POSX],npcdata[p][aid][NPC.POSY],npcdata[p][aid][NPC.NAME], s, x, y, aid, chrdata['mapname'], chrdata['x'], chrdata['y']))
						warpnpc[p] = { aid: [npcdata[p][aid][NPC.NAME]] }
				else:
					self.text.AppendText("warp \"{}\", {}, {};\t// from: {}({}, {}) port : {}\n".format(s, x, y, chrdata['mapname'], chrdata['x'], chrdata['y'], port))
				chrdata['mapname'] = s
				chrdata['x'] = x
				chrdata['y'] = y
				self.mapport.SetValue(str(port))
				self.th.setport(int(self.charport.GetValue()), int(self.mapport.GetValue()))
				self.statusbar.SetStatusText(chrdata['mapname']+':('+str(chrdata['x'])+', '+str(chrdata['y'])+")", 0)
			else:
				self.text.AppendText("@changemapserver Failed packet. \"{}\", x : {}, y : {}, port : {};\n".format(s, x, y, port))
		elif num == 0x087:	#walk
			x = int(((int(fd[8*2:8*2+2],16)&0xF)<<6) + (int(fd[9*2:9*2+2],16)>>2))
			y = int(((int(fd[9*2:9*2+2],16)&0x3)<<8) + int(fd[10*2:10*2+2],16))
			chrdata['x'] = x
			chrdata['y'] = y
			self.statusbar.SetStatusText(chrdata['mapname']+':('+str(chrdata['x'])+', '+str(chrdata['y'])+")", 0)
		elif num == 0x088:	#fixpos
			aid	= RFIFOL(fd,2)
			x	= RFIFOW(fd,6)
			y	= RFIFOW(fd,8)
			p	= self.mapport.GetValue()
			if chrdata['aid'] == aid:
				chrdata['x'] = x
				chrdata['y'] = y
				self.statusbar.SetStatusText(chrdata['mapname']+':('+str(chrdata['x'])+', '+str(chrdata['y'])+")", 0)
			elif p in mobdata.keys():
				if aid in mobdata[p].keys():
					mobdata[p][aid][MOB.POSX] = x
					mobdata[p][aid][MOB.POSY] = y
					#mobdata[p][aid][MOB.POS2X] = 0
					#mobdata[p][aid][MOB.POS2Y] = 0
		elif num == 0x2eb or num == 0xa18:	#authok
			x	= RFIFOPOSX(fd,6)
			y	= RFIFOPOSY(fd,6)
			chrdata['x'] = x
			chrdata['y'] = y
			self.statusbar.SetStatusText(chrdata['mapname']+':('+str(chrdata['x'])+', '+str(chrdata['y'])+")", 0)
		elif num == 0x08d:	#message
			s = fd[8*2:p_len*2]
			s = binascii.unhexlify(s.encode('utf-8')).decode('cp932','ignore')
			s = s.replace("\0","")
			if chrdata['name'] != 'unknown name':
				s = s.replace(chrdata['name'],"\"+strcharinfo(0)+\"")
			aid	= RFIFOL(fd,4)
			p	= self.mapport.GetValue()
			if self.scripttimer.IsChecked() == 1:
				self.text.AppendText('/* ' + str(datetime.now().time()) + ' */\t')
			if chrdata['aid'] == aid:
				self.text.AppendText("unittalk getcharid(3),\""+s+"\",1;\t// self:hidden\n")
			elif p in npcdata.keys() and aid in npcdata[p].keys():
				self.text.AppendText("unittalk getnpcid(0,\""+npcdata[p][aid][NPC.NAME]+"\"),\""+s+"\";\t// " +str(aid)+ "\n")
			elif p in mobdata.keys() and aid in mobdata[p].keys():
				self.text.AppendText("unittalk '@mob_id,\""+s+"\";\t// " +str(aid)+ ":" +mobdata[p][aid][MOB.NAME]+ "\n")
			else:
				self.text.AppendText("@unittalk \""+s+"\";\t// " +str(aid)+ "\n")
		elif num == 0x08e:	#message
			s = fd[4*2:p_len*2]
			s = binascii.unhexlify(s.encode('utf-8')).decode('cp932','ignore')
			s = s.replace("\0","")
			if chrdata['name'] != 'unknown name':
				s = s.replace(chrdata['name'],"\"+strcharinfo(0)+\"")
			if self.scripttimer.IsChecked() == 1:
				self.text.AppendText('/* ' + str(datetime.now().time()) + ' */\t')
			self.text.AppendText("unittalk getcharid(3),\""+s+"\",1;\t// self:hidden\n")
		elif num == 0x2c1:	#multicolormessage
			s = fd[12*2:p_len*2-2]
			s = binascii.unhexlify(s.encode('utf-8')).decode('cp932','ignore')
			aid	= RFIFOL(fd,4)
			color	= RFIFOL(fd,8)
			color = (color & 0x0000FF) >> 16 | (color & 0x00FF00) | (color & 0xFF0000) << 16;
			p	= self.mapport.GetValue()
			if self.scripttimer.IsChecked() == 1:
				self.text.AppendText('/* ' + str(datetime.now().time()) + ' */\t')
			if p in mobdata.keys():
				if aid in mobdata[p].keys():
					self.text.AppendText("@monstertalk \""+s+"\", color: " +str(color)+ ", id: " +str(aid)+ "\n")
			else:
				self.text.AppendText("@talk \""+s+"\", color: " +str(color)+ ", id: " +str(aid)+ "\n")
		elif num == 0x8b3:	#showscript
			s = fd[8*2:p_len*2-2]
			s = binascii.unhexlify(s.encode('utf-8')).decode('cp932','ignore')
			aid	= RFIFOL(fd,4)
			p	= self.mapport.GetValue()
			if self.scripttimer.IsChecked() == 1:
				self.text.AppendText('/* ' + str(datetime.now().time()) + ' */\t')
			if chrdata['aid'] == aid:
				self.text.AppendText("showmessage \"{}\",\"\";\t// self:hidden\n".format(s))
			elif p in npcdata.keys():
				if aid in npcdata[p].keys():
					self.text.AppendText("showmessage \""+s+"\",\""+npcdata[p][aid][NPC.NAME]+"\";\t// " +str(aid)+ "\n")
			elif p in mobdata.keys():
				if aid in mobdata[p].keys():
					self.text.AppendText("@showmessage \""+s+"\";\t// " +str(aid)+ ":" +mobdata[p][aid][MOB.NAME]+ "\n")
		elif num == 0xa37:	#getitem
			upgrade = 0
			idx		= RFIFOW(fd,2)
			amount	= RFIFOW(fd,4)
			itemid	= RFIFOL(fd,6)
			identify = RFIFOB(fd,10)
			limit	= RFIFOL(fd,35)

			if limit > 0:
				upgrade = 1
			equip	= RFIFOL(fd,29)
			if equip > 0:
				refine	= RFIFOB(fd,12)
				card1	= RFIFOL(fd,13)
				card2	= RFIFOL(fd,17)
				card3	= RFIFOL(fd,21)
				card4	= RFIFOL(fd,25)
				opt1id	= RFIFOW(fd,41)
				opt1val	= RFIFOW(fd,43)
				opt2id	= RFIFOW(fd,46)
				opt2val	= RFIFOW(fd,48)
				opt3id	= RFIFOW(fd,51)
				opt3val	= RFIFOW(fd,53)
				opt4id	= RFIFOW(fd,56)
				opt4val	= RFIFOW(fd,58)
				opt5id	= RFIFOW(fd,61)
				opt5val	= RFIFOW(fd,63)
				if refine > 0 or card1 > 0 or card2 > 0 or card3 > 0 or card4 > 0:
					upgrade = 1
				if opt1id > 0:
					upgrade = 2
			if idx in inventory['item'].keys():
				nameid = inventory['item'][idx]["Nameid"]
				if itemid == nameid:
					n = inventory['item'][idx]["Amount"]
					inventory['item'][idx]["Amount"] = n + amount
					if upgrade == 2:
						self.text.AppendText("getoptitem {},{},{},0,{},{},{},{},0,{};\t//opt: {},{}, {},{}, {},{}, {},{}, {},{};\n".format(itemid,identify,refine,card1,card2,card3,card4,limit,getrandopt(opt1id),opt1val,getrandopt(opt2id),opt2val,getrandopt(opt3id),opt3val,getrandopt(opt4id),opt4val,getrandopt(opt5id),opt5val))
					elif upgrade == 1:
						self.text.AppendText("getitem2 {},{},{},{},0,{},{},{},{},{};\n".format(itemid,amount,identify,refine,card1,card2,card3,card4,limit))
					else:
						self.text.AppendText("getitem {},{};\n".format(itemid,amount))
				else:
					if upgrade == 2:
						self.text.AppendText("@getoptitem {},{},{},0,{},{},{},{},0,{};\t//unexpected error opt: {},{}, {},{}, {},{}, {},{}, {},{};\n".format(itemid,identify,refine,card1,card2,card3,card4,limit,getrandopt(opt1id),opt1val,getrandopt(opt2id),opt2val,getrandopt(opt3id),opt3val,getrandopt(opt4id),opt4val,getrandopt(opt5id),opt5val))
					elif upgrade == 1:
						self.text.AppendText("@getitem2 {},{},{},{},0,{},{},{},{},{};\t//unexpected error\n".format(itemid,amount,identify,refine,card1,card2,card3,card4,limit))
					else:
						self.text.AppendText("@getitem {},{};\t//unexpected error\n".format(itemid,amount))
			else:
				inventory['item'][idx] = {"Nameid": itemid, "Amount": amount}
				if upgrade == 2:
					self.text.AppendText("getoptitem {},{},{},0,{},{},{},{},0,{};\t//opt: {},{}, {},{}, {},{}, {},{}, {},{};\n".format(itemid,identify,refine,card1,card2,card3,card4,limit,getrandopt(opt1id),opt1val,getrandopt(opt2id),opt2val,getrandopt(opt3id),opt3val,getrandopt(opt4id),opt4val,getrandopt(opt5id),opt5val))
				elif upgrade == 1:
					self.text.AppendText("getitem2 {},{},{},{},0,{},{},{},{},{};\n".format(itemid,amount,identify,refine,card1,card2,card3,card4,limit))
				else:
					self.text.AppendText("getitem {},{};\n".format(itemid,amount))
		elif num == 0xb41:	#getitem
			upgrade = 0
			refine	= 0
			card1	= 0
			card2	= 0
			card3	= 0
			card4	= 0
			idx		= RFIFOW(fd,2)
			amount	= RFIFOW(fd,4)
			itemid	= RFIFOL(fd,6)
			identify = RFIFOB(fd,10)
			limit	= RFIFOL(fd,34)

			if limit > 0:
				upgrade = 1
			equip	= RFIFOL(fd,28)
			if equip > 0:
				refine	= RFIFOB(fd,68)
				card1	= RFIFOL(fd,12)
				card2	= RFIFOL(fd,16)
				card3	= RFIFOL(fd,20)
				card4	= RFIFOL(fd,24)
				opt1id	= RFIFOW(fd,40)
				opt1val	= RFIFOW(fd,42)
				opt2id	= RFIFOW(fd,45)
				opt2val	= RFIFOW(fd,47)
				opt3id	= RFIFOW(fd,50)
				opt3val	= RFIFOW(fd,52)
				opt4id	= RFIFOW(fd,55)
				opt4val	= RFIFOW(fd,57)
				opt5id	= RFIFOW(fd,60)
				opt5val	= RFIFOW(fd,62)
				if refine > 0 or card1 > 0 or card2 > 0 or card3 > 0 or card4 > 0:
					upgrade = 1
				if opt1id > 0:
					upgrade = 2
			if idx in inventory['item'].keys():
				nameid = inventory['item'][idx]["Nameid"]
				if itemid == nameid:
					n = inventory['item'][idx]["Amount"]
					inventory['item'][idx]["Amount"] = n + amount
					if upgrade == 2:
						self.text.AppendText("getoptitem {},{},{},0,{},{},{},{},0,{};\t//opt: {},{}, {},{}, {},{}, {},{}, {},{};\n".format(itemid,identify,refine,card1,card2,card3,card4,limit,getrandopt(opt1id),opt1val,getrandopt(opt2id),opt2val,getrandopt(opt3id),opt3val,getrandopt(opt4id),opt4val,getrandopt(opt5id),opt5val))
					elif upgrade == 1:
						self.text.AppendText("getitem2 {},{},{},{},0,{},{},{},{},{};\n".format(itemid,amount,identify,refine,card1,card2,card3,card4,limit))
					else:
						self.text.AppendText("getitem {},{};\n".format(itemid,amount))
				else:
					if upgrade == 2:
						self.text.AppendText("@getoptitem {},{},{},0,{},{},{},{},0,{};\t//unexpected error opt: {},{}, {},{}, {},{}, {},{}, {},{};\n".format(itemid,identify,refine,card1,card2,card3,card4,limit,getrandopt(opt1id),opt1val,getrandopt(opt2id),opt2val,getrandopt(opt3id),opt3val,getrandopt(opt4id),opt4val,getrandopt(opt5id),opt5val))
					elif upgrade == 1:
						self.text.AppendText("@getitem2 {},{},{},{},0,{},{},{},{},{};\t//unexpected error\n".format(itemid,amount,identify,refine,card1,card2,card3,card4,limit))
					else:
						self.text.AppendText("@getitem {},{};\t//unexpected error\n".format(itemid,amount))
			else:
				inventory['item'][idx] = {"Nameid": itemid, "Amount": amount}
				if upgrade == 2:
					self.text.AppendText("getoptitem {},{},{},0,{},{},{},{},0,{};\t//opt: {},{}, {},{}, {},{}, {},{}, {},{};\n".format(itemid,identify,refine,card1,card2,card3,card4,limit,getrandopt(opt1id),opt1val,getrandopt(opt2id),opt2val,getrandopt(opt3id),opt3val,getrandopt(opt4id),opt4val,getrandopt(opt5id),opt5val))
				elif upgrade == 1:
					self.text.AppendText("getitem2 {},{},{},{},0,{},{},{},{},{};\n".format(itemid,amount,identify,refine,card1,card2,card3,card4,limit))
				else:
					self.text.AppendText("getitem {},{};\n".format(itemid,amount))
		elif num == 0x0af or num == 0x229:	#delitem

			idx		= RFIFOW(fd,2)
			amount	= RFIFOW(fd,4)
			if idx in inventory['item'].keys():
				nameid = inventory['item'][idx]["Nameid"]
				values = inventory['item'][idx]["Amount"] - amount
				if values <= 0:
					del inventory['item'][idx]
				else:
					inventory['item'][idx]["Amount"] = values
				self.text.AppendText("delitem {},{};\n".format(nameid,amount))
			else:
				self.text.AppendText("@delitem idx:{},{};\t//NotFound\n".format(idx,amount))
		elif num == 0x7fa:	#delitem
			idx		= RFIFOW(fd,4)
			amount	= RFIFOW(fd,6)
			if idx in inventory['item'].keys():
				nameid = inventory['item'][idx]["Nameid"]
				values = inventory['item'][idx]["Amount"] - amount
				if values <= 0:
					del inventory['item'][idx]
				else:
					inventory['item'][idx]["Amount"] = values
				self.text.AppendText("delitem {},{};\n".format(nameid,amount))
			else:
				self.text.AppendText("@delitem idx:{},{};\t//NotFound\n".format(idx,amount))
		elif num == 0x2cb:	#mdcreate
			s = fd[2*2:63*2-2]
			s = binascii.unhexlify(s.encode('utf-8')).decode('cp932','ignore')
			s = s.replace("\0","")
			self.text.AppendText("mdcreate \"{}\";\n".format(s))
		elif num == 0x983:	#status_change
			type	= RFIFOW(fd,2)
			aid		= RFIFOL(fd,4)
			flag	= RFIFOB(fd,8)
			mtick	= RFIFOL(fd,9)
			tick	= RFIFOL(fd,13)
			val1	= RFIFOL(fd,17)
			val2	= RFIFOL(fd,21)
			val3	= RFIFOL(fd,25)
			if self.hiddenbattle.IsChecked() == 1:
				pass
			elif mtick == 9999:
				if chrdata['aid'] == aid:
					if type == 665:	#EFST_ACTIVE_MONSTER_TRANSFORM
						self.text.AppendText("@active_montransform {};\t// self\n".format(val1))
					else:
						self.text.AppendText("@sc_start3 {},{},{},{},0,{},{},{};\t// self\n".format(getefst(type),val1,val2,val3,mtick,tick,flag))
			else:
				p	= self.mapport.GetValue()
				if chrdata['aid'] == aid:
					self.text.AppendText("@sc_start3 {},{},{},{},0,{},{};\t// self, tick={}\n".format(getefst(type),val1,val2,val3,mtick,flag,tick))
				elif p in mobdata.keys():
					if aid in mobdata[p].keys():
						self.text.AppendText("@sc_start3 {},{},{},{},0,{},{};\t// {}, tick={}\n".format(getefst(type),val1,val2,val3,mtick,flag,aid,tick))
		elif num == 0x43f:	#status_change
			type	= RFIFOW(fd,2)
			aid		= RFIFOL(fd,4)
			flag	= RFIFOB(fd,8)
			tick	= RFIFOL(fd,9)
			val1	= RFIFOL(fd,13)
			val2	= RFIFOL(fd,17)
			val3	= RFIFOL(fd,21)
			if self.hiddenbattle.IsChecked() == 1:
				pass
			#elif tick == 9999:
				#pass
			else:
				p	= self.mapport.GetValue()
				if chrdata['aid'] == aid:
					self.text.AppendText("@sc_start3 {},{},{},{},0,{},{};\t// self\n".format(getefst(type),val1,val2,val3,tick,flag))
				elif p in mobdata.keys():
					if aid in mobdata[p].keys():
						self.text.AppendText("@sc_start3 {},{},{},{},0,{},{};\t// {}\n".format(getefst(type),val1,val2,val3,tick,flag,aid))
		elif num == 0x8ff:	#seteffect_enter
			aid		= RFIFOL(fd,2)
			type	= RFIFOW(fd,6)
			tick	= RFIFOL(fd,8)
			val1	= RFIFOL(fd,12)
			val2	= RFIFOL(fd,16)
			val3	= RFIFOL(fd,20)
			if self.hiddenbattle.IsChecked() == 1:
				pass
			#elif tick == 9999 or type == 993:
				#pass
			else:
				p	= self.mapport.GetValue()
				if chrdata['aid'] == aid:
					self.text.AppendText("@effect_enter {},{},{},{},0,{};\t// self\n".format(getefst(type),val1,val2,val3,tick))
				elif p in mobdata.keys():
					if aid in mobdata[p].keys():
						self.text.AppendText("@effect_enter {},{},{},{},0,{},{};\t// {}\n".format(getefst(type),val1,val2,val3,tick,flag,aid))
		elif num == 0x984:	#seteffect_enter
			aid		= RFIFOL(fd,2)
			type	= RFIFOW(fd,6)
			mtick	= RFIFOL(fd,8)
			tick	= RFIFOL(fd,12)
			val1	= RFIFOL(fd,16)
			val2	= RFIFOL(fd,20)
			val3	= RFIFOL(fd,24)
			if self.hiddenbattle.IsChecked() == 1:
				pass
			#elif mtick == 9999 or type == 993:
				#pass
			else:
				p	= self.mapport.GetValue()
				if chrdata['aid'] == aid:
					self.text.AppendText("@effect_enter {},{},{},{},0,{};\t// self\n".format(getefst(type),val1,val2,val3,mtick))
				elif p in mobdata.keys():
					if aid in mobdata[p].keys():
						self.text.AppendText("@effect_enter {},{},{},{},0,{};\t// {}\n".format(getefst(type),val1,val2,val3,mtick,aid))
		elif num == 0x196:	#status_load
			type	= RFIFOW(fd,2)
			aid		= RFIFOL(fd,4)
			flag	= RFIFOB(fd,8)
			if self.hiddenbattle.IsChecked() == 1:
				pass
			elif type == 46 or type == 622 or type == 673 or type == 993:
				pass
			else:
				p	= self.mapport.GetValue()
				if chrdata['aid'] == aid:
					if flag == 0:
						self.text.AppendText("@sc_end {};\t// self\n".format(getefst(type)))
					else:
						self.text.AppendText("@status_load type: {}, flag: {}\t// self\n".format(getefst(type),flag))
				elif p in mobdata.keys():
					if aid in mobdata[p].keys():
						if flag == 0:
							self.text.AppendText("sc_end {},{};\n".format(getefst(type),aid))
						else:
							self.text.AppendText("@status_load type: {}, aid: {}, flag: {}\t\n".format(getefst(type),aid,flag))
		elif num == 0xadf:	#charname_req
			aid			= RFIFOL(fd,2)
			group_id	= RFIFOL(fd,6)
			p	= self.mapport.GetValue()
			s = fd[10*2:34*2-2]
			s = binascii.unhexlify(s.encode('utf-8')).decode('cp932','ignore')
			#s = "" if s[0] == '\0' else s
			#s = s.replace("\0","")
			s = s[:s.find('\0')]
			t = fd[34*2:]
			t = binascii.unhexlify(t.encode('utf-8')).decode('cp932','ignore')
			#t = "" if t[0] == '\0' else t
			#t = t.replace("\0","")
			t = t[:t.find('\0')]
			if p in npcdata.keys():
				if aid in npcdata[p].keys():
					if group_id != 0:
						self.text.AppendText("setnpcgroup "+ str(group_id) + ";\t// NPC:" +str(s)+ "(" +str(aid)+ ")\n")
					if len(t) > 0:
						self.text.AppendText("setnpctitle \""+ t + "\";\t// NPC:" +str(s)+ "(" +str(aid)+ ")\n")
			elif p in mobdata.keys():
				if aid in mobdata[p].keys():
					if group_id != 0:
						self.text.AppendText("setunitgroup "+ str(group_id) + ";\t// MOB:" +str(s)+ "(" +str(aid)+ ")\n")
					if len(t) > 0:
						self.text.AppendText("setunittitle \""+ t + "\";\t// MOB:" +str(s)+ "(" +str(aid)+ ")\n")
		elif num == 0xa24:	#acievement update
			nameid = RFIFOL(fd,16)
			if self.scripttimer.IsChecked() == 1:
				self.text.AppendText('/* ' + str(datetime.now().time()) + ' */\t')
			self.text.AppendText("achievement {};\n".format(nameid))
		elif num == 0xab9:	#itempreview
			index = RFIFOW(fd,2) - 2
			if self.scripttimer.IsChecked() == 1:
				self.text.AppendText('/* ' + str(datetime.now().time()) + ' */\t')
			self.text.AppendText("itempreview {};\n".format(index))
		elif num == 0xb13:	#itempreview
			index = RFIFOW(fd,2) - 2
			if self.scripttimer.IsChecked() == 1:
				self.text.AppendText('/* ' + str(datetime.now().time()) + ' */\t')
			self.text.AppendText("itempreview {};\n".format(index))
		elif num == 0x1d6:	#mapproperty
			type = RFIFOW(fd,2)
			self.text.AppendText("@mapproperty map: "+chrdata['mapname']+", type: "+ str(type) + "\n")
		elif num == 0x99b:	#mapproperty_r
			type	= RFIFOW(fd,2)
			bit		= RFIFOL(fd,4)
			self.text.AppendText("@mapproperty_r map: "+chrdata['mapname']+", type: "+ str(type) + ", bit: "+ str(hex(bit)) +"\n")
		elif num == 0x977:	#hp_info
			aid		= RFIFOL(fd,2)
			hp		= RFIFOL(fd,6)
			maxhp	= RFIFOL(fd,10)
			p	= self.mapport.GetValue()
			if p in mobdata.keys():
				if aid in mobdata[p].keys():
					self.text.AppendText("@hpinfo name: "+ mobdata[p][aid][MOB.NAME] + ", class: "+ str(mobdata[p][aid][MOB.CLASS]) +", HP: " +str(hp)+ "/" +maxhp+ "\n")
		elif num == 0xa36:	#hp_info_tiny
			aid	= RFIFOL(fd,2)
			per	= RFIFOB(fd,6)
			per	= int(per) * 5
			p	= self.mapport.GetValue()
			self.text.AppendText("@hp_info_tiny name: "+ mobdata[p][aid][MOB.NAME] + ", class: "+ str(mobdata[p][aid][MOB.CLASS]) +", per: "+ str(per) +"%\n")
		elif num == 0x283:	#account_id
			aid	= RFIFOL(fd,2)
			chrdata['aid'] = aid
		elif num == 0xb09 or num == 0xb0a:	#inventory
			s_len = RFIFOW(fd,2)
			type = RFIFOB(fd,4)
			if type == 0:
				c = 34 if num == 0xb09 else 67
				i = 0
				while i*c+5 < s_len:
					idx    = RFIFOW(fd, i*c+5)
					nameid = RFIFOL(fd, i*c+7)
					amount = RFIFOW(fd, i*c+12) if num == 0xb09 else 1
					inventory['item'][idx] = {"Nameid": nameid, "Amount": amount}
					i += 1
		elif num == 0xb38 or num == 0xb39:	#inventory
			s_len = RFIFOW(fd,2)
			type = RFIFOB(fd,4)
			if type == 0:
				c = 35 if num == 0xb38 else 68
				i = 0
				while i*c+5 < s_len:
					idx    = RFIFOW(fd, i*c+5)
					nameid = RFIFOL(fd, i*c+7)
					amount = RFIFOW(fd, i*c+12) if num == 0xb38 else 1
					inventory['item'][idx] = {"Nameid": nameid, "Amount": amount}
					i += 1
		elif num == 0x446:	#showevent
			aid	= RFIFOL(fd,2)
			x	= RFIFOW(fd,6)
			y	= RFIFOW(fd,8)
			state	= RFIFOW(fd,10)
			type	= RFIFOW(fd,12)
			p	= self.mapport.GetValue()
			if p in npcdata.keys():
				if aid in npcdata[p].keys():
					self.text.AppendText("showevent "+str(state)+", "+str(type)+", \""+npcdata[p][aid][NPC.NAME]+"\";\t// " +str(aid)+ ": "+str(x)+", "+str(y)+"\n")
				else:
					self.text.AppendText("@showevent "+str(state)+", "+str(type)+";\t// " +str(aid)+ ": "+str(x)+", "+str(y)+"\n")
			else:
				self.text.AppendText("@showevent "+str(state)+", "+str(type)+"\";\t// " +str(aid)+ ": "+str(x)+", "+str(y)+"\n")
		elif num == 0xa3b:	#hat_effect
			aid      = RFIFOL(fd,4)
			enable   = RFIFOB(fd,8)
			effectId = RFIFOW(fd,9)
			if chrdata['aid'] == aid:
				if enable > 0:
					self.text.AppendText("@hat_effect {}\n".format(effectId))
				else:
					self.text.AppendText("@hat_effect_end {}\n".format(effectId))
		elif num == 0x29b:	#makemerc
			aid   = RFIFOL(fd,2)
			limit = RFIFOL(fd,64)
			i = 22
			s = fd[i*2:(i+24)*2]
			s = binascii.unhexlify(s.encode('utf-8')).decode('cp932','ignore')
			s = s.replace("\0","")
			self.text.AppendText("@makemerc time: {}\t// {}({})\n".format(limit,s,aid))
		elif num == 0xb0d:	#delmisceffect
			aid  = RFIFOL(fd,2)
			type = RFIFOL(fd,6)
			p	= self.mapport.GetValue()
			if p in npcdata.keys():
				if aid in npcdata[p].keys():
					self.text.AppendText("delmisceffect {}, \"{}\";\t// {}\n".format(type,npcdata[p][aid][NPC.NAME],aid))
				else:
					self.text.AppendText("@delmisceffect {};\t// {}\n".format(type,aid))
			else:
				self.text.AppendText("@delmisceffect {};\t// {}\n".format(type,aid))
		elif num == 0x287:	#cashshop
			i = 0
			s = ""
			while i*13+8 < p_len:
				if i > 0:
					s += ","
				s	+= str(RFIFOL(fd,17+i*13))
				s	+= ":"
				s	+= str(RFIFOL(fd,8+i*13))
				i += 1
			self.text.AppendText(chrdata['mapname']+",0,0,0\tcashshop\tcall_shop_name\t-1," + s +"\n")
		elif num == 0xb0e:	#npcexchange
			i = 0
			s = ""
			while i*25+4 < p_len:
				if i > 0:
					s += ","
				s	+= str(RFIFOL(fd,4+i*25))
				s	+= ":"
				s	+= str(RFIFOL(fd,13+i*25))
				s	+= ":"
				s	+= str(RFIFOW(fd,17+i*25))
				i += 1
			aid = self.tmp_id
			p = self.mapport.GetValue()
			if aid == 0:
				m = chrdata["mapname"]
				self.text.AppendText("-\texchange\t"+ m[:-4] +"#callexchange\t-1," +s +"\t// selfpos("+ str(chrdata["x"])+", "+ str(chrdata["y"]) +")\n")
			else:
				if p in npcdata.keys():
					if aid in npcdata[p].keys():
						self.text.AppendText(npcdata[p][aid][NPC.MAP]+","+ str(npcdata[p][aid][NPC.POSX]) + ","+ str(npcdata[p][aid][NPC.POSY]) +","+ str(npcdata[p][aid][NPC.POSD]) +"\texchange\t"+ str(npcdata[p][aid][NPC.NAME]) +"\t"+ str(npcdata[p][aid][NPC.CLASS]) + "," +s +"\t// "+ str(aid) +"\n")
			self.tmp_id = 0
		elif num == 0xb56:	#npcbartershop
			i = 0
			d = 0
			s = ""
			while i*26+d+8 < p_len:
				if i > 0:
					s += ","
				s	+= str(RFIFOL(fd,8+i*26+d))
				s	+= ":"
				num	= RFIFOL(fd,12+i*26+d)
				if num == 4294901764:
					num = -1
				s	+= str(num)
				s	+= ":"
				s	+= str(RFIFOL(fd,26+i*26+d))
				c	=  RFIFOL(fd,30+i*26+d)
				s	+= " { "
				s	+= str(RFIFOL(fd,34+i*26+d))
				s	+= ":"
				num	= RFIFOL(fd,38+i*26+d)
				if num == 6553600:
					num = -1
				s	+= str(num)
				s	+= ":"
				s	+= str(RFIFOL(fd,40+i*26+d))
				if c >= 2:
					s	+= ", "
					s	+= str(RFIFOL(fd,46+i*26+d))
					s	+= ":"
					num	= RFIFOL(fd,50+i*26+d)
					if num == 6553600:
						num = -1
					s	+= str(num)
					s	+= ":"
					s	+= str(RFIFOL(fd,52+i*26+d))
				if c == 3:
					s	+= ", "
					s	+= str(RFIFOL(fd,58+i*26+d))
					s	+= ":"
					num	= RFIFOL(fd,62+i*26+d)
					if num == 6553600:
						num = -1
					s	+= str(num)
					s	+= ":"
					s	+= str(RFIFOL(fd,64+i*26+d))
				s	+= " }"
				d	+= c * 12
				i += 1
			aid = self.tmp_id
			p = self.mapport.GetValue()
			if aid == 0:
				m = chrdata["mapname"]
				self.text.AppendText("-\tbarter\t"+ m[:-4] +"#callbarter\t-1," +s +"\t// selfpos("+ str(chrdata["x"])+", "+ str(chrdata["y"]) +")\n")
			else:
				if p in npcdata.keys():
					if aid in npcdata[p].keys():
						self.text.AppendText(npcdata[p][aid][NPC.MAP]+","+ str(npcdata[p][aid][NPC.POSX]) + ","+ str(npcdata[p][aid][NPC.POSY]) +","+ str(npcdata[p][aid][NPC.POSD]) +"\tbarter\t"+ str(npcdata[p][aid][NPC.NAME]) +"\t"+ str(npcdata[p][aid][NPC.CLASS]) + "," +s +"\t// "+ str(aid) +"\n")
			self.tmp_id = 0
		elif num == 0xba2:	#messize
			height  = RFIFOL(fd,2)
			width   = RFIFOL(fd,6)
			if self.scripttimer.IsChecked() == 1:
				self.text.AppendText('/* ' + str(datetime.now().time()) + ' */\t')
			self.text.AppendText("messize {},{};\n".format(height,width))
		elif num == 0xba3 or num == 0xbb5:	#dialogpos
			x = RFIFOL(fd,2)
			y = RFIFOL(fd,6)
			if self.scripttimer.IsChecked() == 1:
				self.text.AppendText('/* ' + str(datetime.now().time()) + ' */\t')
			self.text.AppendText("mespos {},{};\n".format(x,y))
		elif num == 0xba1:	#mesalign
			align = RFIFOB(fd,2)
			if self.scripttimer.IsChecked() == 1:
				self.text.AppendText('/* ' + str(datetime.now().time()) + ' */\t')
			self.text.AppendText("mesalign {};\n".format(align))
		elif Configuration['Show_OtherPacket'] == 1:
			self.text.AppendText("@packet "+ n + ".\n")

app = wx.App()
read_packet_db()
read_ignore_db()
read_config_db()
MARiA_Frame(None, -1, "MARiA  "+MARiA_VERSION)
app.MainLoop()
