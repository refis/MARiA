# -*- coding: utf-8 -*-

import wx
import threading
import binascii
from scapy.all import *

Packetlen = {}
chrdata = {}
mobdata = {}
npcdata = {}
warpnpc = {}

RFIFOB = lambda p, pos: int(p[pos*2:pos*2+2],16)
RFIFOW = lambda p, pos: int(p[pos*2+2:pos*2+4]+p[pos*2:pos*2+2],16)
RFIFOL = lambda p, pos: int(p[pos*2+6:pos*2+8]+p[pos*2+4:pos*2+6]+p[pos*2+2:pos*2+4]+p[pos*2:pos*2+2],16)
RFIFOQ = lambda p, pos: int(p[pos*2+14:pos*2+16]+p[pos*2+12:pos*2+14]+p[pos*2+10:pos*2+12]+p[pos*2+8:pos*2+10]+p[pos*2+6:pos*2+8]+p[pos*2+4:pos*2+6]+p[pos*2+2:pos*2+4]+p[pos*2:pos*2+2],16)
RFIFOPOSX = lambda p, pos: (int(p[pos*2:pos*2+2],16)<<2) + ((int(p[pos*2+2:pos*2+4],16)&0xc0)>>6)
RFIFOPOSY = lambda p, pos: ((int(p[pos*2+2:pos*2+4],16)&0x3f)<<4) + ((int(p[pos*2+4:pos*2+6],16)&0xF0)>>4)
RFIFOPOSD = lambda p, pos: (int(p[pos*2+4:pos*2+6],16)&0xF)

def read_packet_db():
	path = './PacketLength.txt'

	with open(path) as f:
		for s_line in f:
			if s_line[0:2] == "//":
				continue
			else:
				l = s_line.split(' ')
				if len(l) >= 2:
					Packetlen[int(l[0],16)] = int(l[1])
				else:
					l = s_line.split(',')
					if len(l) >= 2:
						Packetlen[int(l[0],16)] = int(l[1])

class MARiA_Catch(threading.Thread):
	def __init__(self):
		threading.Thread.__init__(self)
		self.data = ""
		self.port = 5121
		self.pause_flag = True

	def readpause(self):
		return self.pause_flag

	def readdata(self):
		return self.data

	def setdata(self, str):
		self.data = str

	def setport(self, num):
		self.port = num

	def run(self):
		sniff (filter = "ip host 192.168.1.3", prn=self.OnCatch, count=0)

	def c_pause(self,flag):
		self.pause_flag = flag

	def is_this_target_packet(self, packet):
		return TCP in packet and (packet[TCP].sport == self.port or packet[TCP].sport == 6121)

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
					self.data += self.OnHexEx(raw)
		else:
			pass

class MARiA_Frame(wx.Frame):
	Started		= False
	Speed		= 100
	ID_TIMER	= 1
	buf			= ""
	th = MARiA_Catch()
	th.setDaemon(True)

	def __init__(self, parent, id, title):
		wx.Frame.__init__(
			self, 
			parent, 
			id,
			title=title, 
			size=(800,500))

		self.timer = wx.Timer(self, MARiA_Frame.ID_TIMER)

		menubar = wx.MenuBar()
		file = wx.Menu()
		edit = wx.Menu()

		menubar.Append(file, '&File')
		menubar.Append(edit, '&Edit')
		self.SetMenuBar(menubar)

		sp = wx.SplitterWindow(self,-1, style=wx.SP_LIVE_UPDATE)

		vbox = wx.BoxSizer(wx.VERTICAL)
		p1 = wx.Panel(sp, -1)

		hbox1 = wx.BoxSizer(wx.HORIZONTAL)
		st1 = wx.StaticText(p1, -1, 'Map Port:')
		hbox1.Add(st1, 0, wx.LEFT | wx.BOTTOM | wx.TOP, 2)
		self.port = wx.TextCtrl(
			p1,
			-1,
			size=(40,10))
		self.port.WriteText('5121')
		hbox1.Add(self.port, 1, wx.EXPAND)
		st2 = wx.StaticText(p1, -1, 'Active Start:')
		hbox1.Add(st2, 1, wx.RIGHT | wx.BOTTOM | wx.TOP, 2)
		self.button = wx.Button(
			p1,
			-1,
			'Start',
			size=(20,20))
		hbox1.Add(self.button,3)
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

		icon = wx.Icon(r"./icon.ico", wx.BITMAP_TYPE_ICO)
		self.SetIcon(icon)

		p1.SetSizer(vbox)
		p2.SetSizer(vbox2)
		self.Centre()
		self.Show(True)

	def OnStart(self, event):
		if self.Started == False:
			self.th.start()
			self.Started = True
		if self.th.readpause() == True:
			self.th.setport(int(self.port.GetValue()))
			self.th.c_pause(False)
			self.timer.Start(MARiA_Frame.Speed)
			self.button.SetLabel("Stop")
			self.port.Disable()
		else:
			self.th.c_pause(True)
			self.timer.Stop()
			self.button.SetLabel("Start")
			self.port.Enable()

	def OnTimer(self, event):
		if event.GetId() == MARiA_Frame.ID_TIMER:
			data = self.th.readdata()
			if data == "":
				#何もないときに処理する
				self.GetPacket()
			else:
				self.buf += data
				self.th.setdata("")
		else:
			event.Skip()

	def GetPacket(self):
		buf = self.buf
#		if not buf == "":
		while not buf == "":
			total_len = len(buf)
			num = RFIFOW(buf,0)
			if num in Packetlen.keys():
				packet_len = Packetlen[num]
			else:
				packet_len = 2
			if packet_len == -1:
				packet_len = RFIFOW(buf,2)
#				print("num:",hex(num),"packet...:",packet_len,"total:",total_len,"mes:",buf)
#			else:
#				print("num:",hex(num),"packet_len:",packet_len,"total:",total_len,"mes:",buf)
			if packet_len*2 > total_len:	#パケット足りてない
				break
			else:
				i = 0
				if self.btext.GetValue() != '':
					self.btext.AppendText('\n')
				self.btext.AppendText(format(num, '#06x')+": ")
				while i < packet_len*2:
					self.btext.AppendText(buf[i:i+2]+ ' ')
					i += 2
				try:
					if packet_len >= 2:
						self.ReadPacket(num, packet_len)
				except Exception as e:
					print(e)
				if packet_len*2 < total_len:
					self.buf = buf = buf[packet_len*2:total_len]
				else:
					self.buf = buf = ''

	def ReadPacket(self, num, p_len):
		n = hex(num)
		buf = self.buf[0:p_len*2]
		if num == 0x9fe:	#spawn
			if p_len > 83:
				type	= RFIFOB(buf,4)
				aid		= RFIFOL(buf,5)
				speed	= RFIFOW(buf,13)
				option	= RFIFOL(buf,19)
				view	= RFIFOW(buf,23)
				x		= RFIFOPOSX(buf,63)
				y		= RFIFOPOSY(buf,63)
				dir		= RFIFOPOSD(buf,63)
				if type==5 or type==6:
					i = 83
					s = buf[i*2:p_len*2]
					if (s[-2:] >= '80' and s[-2:] <= '9f') or (s[-2:] >= 'e0' and s[-2:] <= '9e'):
						s = s[:-2]
					s = binascii.unhexlify(s.encode('utf-8')).decode('cp932')
					if type == 5:
						self.text.AppendText("@spawn(type: BL_MOB, ID: "+str(aid)+", speed: "+str(speed)+", option: "+str(hex(option))+", class: "+view+", pos: (\"unknown.gat\","+str(x)+","+str(y)+"), dir: "+str(dir)+", name\""+ s +"\")\n")
					elif type == 6:
						self.text.AppendText("unknown.gat,"+ str(x) + ","+ str(y) +","+ str(dir) +"\tscript\t"+ s +"\t"+ str(view) +",{/* "+ str(aid) +" */}\n")
						
		elif num == 0x9ff:	#spawn
			if p_len > 84:
				type	= RFIFOB(buf,4)
				aid		= RFIFOL(buf,5)
				speed	= RFIFOW(buf,13)
				option	= RFIFOL(buf,19)
				view	= RFIFOW(buf,23)
				x		= RFIFOPOSX(buf,63)
				y		= RFIFOPOSY(buf,63)
				dir		= RFIFOPOSD(buf,63)
				if type==5 or type==6:
					i = 84
					s = buf[i*2:p_len*2]
					opt = ""
					if option == 2:
						opt = "(hide)"
					elif option == 4:
						opt = "(cloaking)"
					if (s[-2:] >= '80' and s[-2:] <= '9f') or (s[-2:] >= 'e0' and s[-2:] <= '9e'):
						s = s[:-2]
					s = binascii.unhexlify(s.encode('utf-8')).decode('cp932')
					if type == 5:
						self.text.AppendText("@spawn(type: BL_MOB, ID: "+str(aid)+", speed: "+str(speed)+", option: "+str(hex(option))+", class: "+view+", pos: (\"unknown.gat\","+str(x)+","+str(y)+"), dir: "+str(dir)+", name\""+ s +"\")\n")
					elif type == 6:
						self.text.AppendText("unknown.gat,"+ str(x) + ","+ str(y) +","+ str(dir) +"\tscript\t"+ s +"\t"+ str(view) +",{/* "+ str(aid) +" "+opt+"*/}\n")
		elif num == 0x0b4:	#mes
			s = buf[8*2:p_len*2-2]
			s = binascii.unhexlify(s.encode('utf-8')).decode('cp932')
			self.text.AppendText("mes \""+ s + "\";\n")
		elif num == 0x0b5:	#next
			self.text.AppendText("next;\n")
		elif num == 0x0b6:	#close
			self.text.AppendText("close;\n")
		elif num == 0x0b7:	#select
			s = buf[8*2:p_len*2-4]
			s = binascii.unhexlify(s.encode('utf-8')).decode('cp932')
			l = s.split(':')
			if len(l) == 1:
				self.text.AppendText("menu \""+s+"\",-;\n")
			else:
				self.text.AppendText("select(\""+s.replace(':','\",\"')+"\")\n")
		elif num == 0x142:	#input num
			self.text.AppendText("input '@num;\n")
		elif num == 0x1d4:	#input str
			self.text.AppendText("input '@str$;\n")
		elif num == 0x1b3:	#cutin
			s = buf[2*2:p_len*2-2]
			s = binascii.unhexlify(s.encode('utf-8')).decode('cp932')
			type	= RFIFOB(buf,66)
			self.text.AppendText("cutin \""+s+"\", "+str(type)+";\n")
		elif num == 0x07f:	#server tick
			pass
		elif num == 0x087:	#move_ack
			pass
		elif num == 0x187:	#alive
			pass
		else:
			self.text.AppendText("@packet "+ n + ".\n")

app = wx.App()
read_packet_db()
MARiA_Frame(None, -1, "MARiA")
app.MainLoop()
