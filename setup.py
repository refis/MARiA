# coding: utf-8

############### cx_Freeze 用セットアップファイル ##########
# コマンドライン上で python setup.py buildとすると、exe化　#
# Mac用のAppを作成するには、buildをbdist_macとする        #
######################################################
 
import sys, os
from cx_Freeze import setup, Executable

#TCL, TKライブラリのエラーが発生する場合に備え、以下を設定
#参考サイト：http://oregengo.hatenablog.com/entry/2016/12/23/205550
if sys.platform == "win32":
    base = "Win32GUI" # "Win32GUI" ←GUI有効
    #Windowsの場合の記載　それぞれの環境によってフォルダの数値等は異なる
    #os.environ['TCL_LIBRARY'] = "C:\\Users\\user\\AppData\\Local\\Programs\\Python\\Python38-32\\tcl\\tcl8.6"
    #os.environ['TK_LIBRARY'] = "C:\\Users\\user\\AppData\\Local\\Programs\\Python\\Python38-32\\tcl\\tk8.6"
else:
    base = "Win32GUI" # "Win32GUI"

#importして使っているライブラリを記載
packages = []

#importして使っているライブラリを記載（こちらの方が軽くなるという噂）
includes = [
    "wx",
    "threading",
    "binascii",
    "time",
    "traceback",
    "scapy",
    "enum",
]

excludes = [
]

##### 細かい設定はここまで #####

#アプリ化したい pythonファイルの指定触る必要はない
exe = Executable(
    script = "maria.py",
    icon = "icon.ico",
    base = base
)

# セットアップ
setup(name = 'MARiA',
      options = {
          "build_exe": {
              "packages": packages, 
              "includes": includes, 
              "excludes": excludes,
          }
      },
      version = '0.1',
      description = 'converter',
      executables = [exe])
