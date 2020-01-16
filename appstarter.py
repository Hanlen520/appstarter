#coding: utf-8

import os, subprocess, sys, platform
import threading, time, datetime
import logging, argparse
from inter.packageinfo_get import getpkg as packageinfo_get_getpkg
import urllib.request
import zipfile
import shutil

logging.basicConfig(level = logging.INFO, format='%(asctime)s - %(levelname)s [%(filename)s:%(lineno)d]: %(message)s')
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.ERROR)


def execShellDaemon(cmd):
    return subprocess.Popen(cmd, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)

def execShell(cmd, t=120):
    ret = {}
    try:
        p = subprocess.run(cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE, shell=True, encoding='utf-8', timeout=t)
        if p.returncode == 0:
            ret['d'] = p.stdout
        else:
            ret['e'] = p.stderr
    except subprocess.TimeoutExpired:
        ret['e'] = 'timeout'

    return ret

class AppStarter(object):
    def __init__(self, did):
        self._adb = 'adb'
        self._frida = 'frida -U '
        self._did = did
        self._devicepkg = []
        self._curdir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '')
        self._dirapps = os.path.join(self._curdir, 'apps', '')
        self._dirappstmp = os.path.join(self._dirapps, 'tmp', '')
        self._dirinter = os.path.join(self._curdir, 'inter', '')
        self._androidver = ''
        self._blacklist = [
            'com.android.settings',
            'com.topjohnwu.magisk',
            'com.speedsoftware.rootexplorer'
        ]

        self._init()
    
    def _init(self):
        #检测多手机设备情况
        if not self.checkOnline(self._did):
            sys.exit()
        if self._did:
            self._adb = 'adb -s '+self._did
            self._frida =  'frida -D  ' +self._did
        
        #获取手机包列表
        self._devicepkg = self.getDevicePkgs()
        self._androidver = self.getAndroidVer()

        if not self.isPhoneRooted():
            print('[!]phone not rooted, may not work well')

    def monkey(self, pkg, startallcomponent):
        pkgs = getPkgList(pkg)
        self.installPkgList(pkgs)
        self._devicepkg = self.getDevicePkgs()
        from inter.apkcookpy.lib.apk import APKCook
        logging.info('=====start monkey=====')
        
        #设置selinux
        #cmd: Failure calling service activity: Failed transaction
        cmd = self._adb + ' shell "su -c \'setenforce 0\'" '
        ret = execShell(cmd)
        if 'e' in ret.keys():
            logging.error(ret.get('e'))
        
        cmd = self._adb + ' shell  "mkdir /sdcard/monkeylogs"'
        ret = execShell(cmd)
        
        if not self.setupFrida():
            return

        # 权限申请hook
        # 使用thread在ctrl+C情况下，难退出
        #vMIUI直接允许权限申请
        pid = self.getPermissionPid()
        krpjs = self._dirinter+'kill_permission_request.js'
        if pid:
            logging.info('==Hook com.lbe.security.miui:ui  pid:'+pid)
            cmd = self._frida + ' --no-pause -l '+krpjs+' -p '+pid
            permission_frida = execShellDaemon(cmd)
        
        for p in pkgs:
            if p in self._blacklist:
                continue
            if p not in self._devicepkg:
                logging.error(p+' not installed')
                continue
            #检查设备在线
            if not self.checkOnline(self._did):
                logging.error('Device offline')
                return
            #准备apk文件
            sp = self._dirapps+p
            if not os.path.isfile(sp+'.apk'):
                cmd = self._adb + ' shell "pm path  '+p+'"'
                ret = execShell(cmd)
                if 'd' in ret.keys() and ret.get('d'):
                    path = ret.get('d').split(':')[1].strip()
                    logging.info('Pull from device')
                    cmd = self._adb + ' pull '+path+' '+sp
                    ret1 = execShell(cmd)
                    if 'd' in ret1.keys():
                        shutil.move(sp, sp+'.apk')
                    else:
                        logging.error(ret1.get('e'))
                else:
                    logging.error(ret.get('e'))
            
            
            if not os.path.isfile(sp+'.apk'):
                logging.error(p+'.apk not exists')
                continue
            
            logging.info('=='+p)
                
            # frida unload ssl
            usjs = self._dirinter + 'unload_ssl.js'
            cmd =  self._frida + ' --no-pause -l '+usjs+' -f '+p
            ssl_frida = execShellDaemon(cmd)

            # permission hook
            if not pid:
                pid = self.getPermissionPid()
                if pid:
                    alive = True
                    try:
                        if permission_frida.poll():
                            alive = False
                    except Exception:
                        alive = False
                    if not alive:
                        logging.info('==Hook com.lbe.security.miui:ui  pid:'+pid)
                        cmd = self._frida + ' --no-pause -l '+krpjs+' -p '+pid
                        permission_frida = execShellDaemon(cmd)

            #解析activity/service组件
            encrypt = False
            try:
                # has exception
                if startallcomponent:
                    activity = APKCook(sp+'.apk').show('a')
                else:
                    activity = APKCook(sp+'.apk').show('ma').split(',')
                if len(activity) < 2:
                    encrypt = True

                #防止单个activity卡死
                timeout = 120
                timeoutThread = threading.Thread(target=self.timeoutKIll, args=(p, timeout), daemon=True)
                timeoutThread.start()

                cmd = self._adb + ' shell  "rm /sdcard/monkeylogs/'+p+'.log"'
                ret = execShell(cmd)

                for a in activity:
                    logging.info(a)
                    cmd = self._adb + ' shell "su -c \'am start -n '+p+'/'+a+'\' " '
                    #timeout not working, because connected to pipe
                    execShell(cmd, 40)

                    cmd = self._adb + ' shell "su -c \'monkey -p '+p+' -vvv  --throttle 100 --pct-syskeys 0  --ignore-crashes 133 >> /sdcard/monkeylogs/'+p+'.log\' " '
                    execShell(cmd, 40)
                    if not timeoutThread.is_alive():
                        timeoutThread = threading.Thread(target=self.timeoutKIll, args=(p, timeout), daemon=True)
                        timeoutThread.start()

                if startallcomponent:
                    service = APKCook(sp+'.apk').show('s')
                else:
                    service = APKCook(sp+'.apk').show('ms').split(',')
                for s in service:
                    logging.info(s)
                    cmd = self._adb + ' shell "su -c \'am start-service  '+p+'/'+s+'\' " '
                    execShell(cmd, 40)
                    time.sleep(1)

                if startallcomponent:
                    receiver = APKCook(sp+'.apk').show('r')
                else:
                    receiver = APKCook(sp+'.apk').show('mr').split(',')
                for s in receiver:
                    logging.info(s)
                    cmd = self._adb + ' shell "su -c \'am broadcast  '+p+'/'+s+'\' " '
                    execShell(cmd, 40)
                    time.sleep(1)

            except KeyboardInterrupt:
                try:
                    permission_frida.terminate()
                except Exception:
                    pass
                ssl_frida.terminate()
                cmd = self._adb + ' shell "am force-stop '+p+' " '
                ret = execShell(cmd)
                raise KeyboardInterrupt

            except Exception as e:
                # import traceback
                # traceback.print_exc()
                logging.error(str(e))
                encrypt = True
            
            if encrypt:
                cmd = self._adb + ' shell "su -c \'monkey -p '+p+' -vvv  --throttle 100 --pct-syskeys 0  --ignore-crashes 1333 >> /sdcard/monkeylogs/'+p+'.log\' " '
                ret = execShell(cmd)
                # if 'e' in ret.keys():
                #     logging.info(ret.get('e'))

            cmd = self._adb + ' shell "am force-stop '+p+' " '
            ret = execShell(cmd)
            ssl_frida.terminate()
            time.sleep(0.2)
            # cmd = adb + ' shell \' su -c "am force-stop '+p+' "\' '
            # ret = execShell(cmd)
    
    def timeoutKIll(self, pkg, t):
        for i in range(t):
            time.sleep(1)
        cmd = self._adb + ' shell "am force-stop '+pkg+' " '
        execShell(cmd)

    def setupFrida(self):
        cmd = self._adb + ' shell  "ps -A | grep frida"'
        ret = execShell(cmd)
        out = str(ret)
        if 'frida-helper-' not in out:
            cmd = self._adb + ' shell ls  /data/local/tmp/frida'
            ret = execShell(cmd)
            
            if 'No such file' in str(ret) :
                frida = self._dirinter+'frida'
                if not os.path.isfile(frida):
                    logging.error('请配置frida环境(下载frida-arm-server, 重命名frida，放在inter目录)')
                    return False
                cmd = self._adb + ' push '+frida+' /data/local/tmp/frida'
                ret = execShell(cmd)
                if 'd' in ret.keys():
                    logging.info('push frida success')
            
            cmd = self._adb + ' shell "su -c \' chmod +x /data/local/tmp/frida \' " '
            ret = execShell(cmd)
            cmd = self._adb + ' shell "su -c \' /data/local/tmp/frida &\' " '
            ret = execShell(cmd, t=30)
            #print(ret)
            if 'd' in ret.keys():
                cmd = self._adb + ' shell  "ps -A | grep frida"'
                ret2 = execShell(cmd)
                if 'd' in ret2.keys() and 'frida-helper-' in ret2.get('d'):
                    logging.info('frida start success')
                    return True
                else:
                    logging.error('frida start error，请自行安装frida')
                    return False
        else:
            logging.info('frida running ')
            return True

    def isPhoneRooted(self):
        cmd = self._adb + ' shell "su -c \'id\'"'
        ret = execShell(cmd)
        return 'd' in ret.keys()

    def getAndroidVer(self):
        cmd = self._adb + ' shell getprop ro.build.version.release'
        ret = execShell(cmd)
        if 'd' in ret.keys():
            logging.info('android version '+ret.get('d').rstrip('\n'))
            return ret.get('d').rstrip('\n')

    def getDevicePkgs(self):
        ret = execShell(self._adb + ' shell pm list packages')
        pkgs = []
        if 'e' not in ret.keys():
            dt = ret.get('d').split('\n')
            for p in dt:
                if p:
                    pkgs.append(p.split(':')[1])
        else:
            logging.error(ret.get('e'))
        return pkgs
    
    def checkOnline(self, deviceid=''):
        devices = execShell('adb devices -l').get('d').split('\n')
        ret = [d for d in devices if d.find('device ') != -1]
        dids = [d.split()[0] for d in ret]
        if deviceid:
            if deviceid in dids:
                return True
            else:
                print('Device id error')
                print(execShell('adb devices -l').get('d'))
                return False
        else:
            if len(dids) == 0:
                print('No device')
                return False
            elif len(dids) == 1:
                return True
            elif len(dids) > 1:
                print('More than one device, please set -s deviceid')
                return False

    def isDexExist(self, apk):
        #系统app将dex存在其他位置，也可能不存在dex
        zipf = zipfile.ZipFile(apk)
        if 'classes.dex' in zipf.namelist():
            return True
        return False

    def getVersionDevice(self, pkg):
        cmd = self._adb + ' shell "dumpsys package '+pkg+'  | grep versionName" '
        ret = execShell(cmd)
        if ret.get('d'):
            vs = ret.get('d').split('\n')
            for v in vs:
                if v:
                    vv = v.split('=')
                    if len(vv) == 2:
                        return vv[1]
        return False

    def getVersionApk(self, pkg):
        from inter.apkcookpy.lib.apk import APKCook
        try:
            return APKCook(self._dirapps+pkg+'.apk').show('v')
        except:
            return False

    def getVersionOnline(self, pkg):
        return packageinfo_get_getpkg(pkg, True, True)

    def downloadPkgList(self, pkgs):
        '''
        功能：批量下载APK
        '''
        logging.info('======Download======')

        try:
            os.mkdir(self._dirapps)
        except:
            pass
        try:
            os.mkdir(self._dirappstmp)
        except:
            pass
            
        islinux = platform.system() == 'Linux'
        arm64 = True
        cmd = self._adb + ' shell "getprop ro.product.cpu.abi"'
        ret = execShell(cmd)
        if 'd' in ret.keys() and 'arm64' not in ret.get('d'):
            arm64 = False

        #android9出现cdex
        if self._androidver >= '9':
            cdextool = 'cdex_converter64'
            if not arm64:
                cdextool = 'cdex_converter32'
            cmd = self._adb + ' shell "ls /data/local/tmp/'+cdextool+' "'
            ret = execShell(cmd)
            if 'No such file' in str(ret):
                if not os.path.isfile(self._dirinter+cdextool): 
                    logging.info('从android9+ 手机下载app，需要compact-dex-converter')
                    logging.error('先下载{} 链接: https://pan.baidu.com/s/1VMKyJ3n4ubiXeqICNatzYw 提取码: q8fk 保存到inter目录下'.format(cdextool))
                else:
                    cmd = self._adb + ' push '+self._dirinter+cdextool+' /data/local/tmp/'
                    ret = execShell(cmd)
                    if 'd' in ret.keys():
                        logging.info('push compact-dex-converter success')
                    cmd = self._adb + ' shell "su -c \' chmod +x /data/local/tmp/'+cdextool+' \' " '
                    ret = execShell(cmd)
        
        #android7.0出现vdex，在手机上执行转换
        if self._androidver >= '7':
            vdextool = 'vdexExtractor64'
            if not arm64:
                vdextool = 'vdexExtractor32'
            cmd = self._adb + ' shell "ls /data/local/tmp/'+vdextool+' "'
            ret = execShell(cmd)
            if 'No such file' in str(ret):
                if not os.path.isfile(self._dirinter+vdextool):
                    logging.info('从android7+ 手机下载app，需要vdexExtractor')
                    logging.error('先下载{} 链接: https://pan.baidu.com/s/1VMKyJ3n4ubiXeqICNatzYw 提取码: q8fk 保存到inter目录下'.format(vdextool))
                else:
                    cmd = self._adb + ' push '+self._dirinter+vdextool+' /data/local/tmp/'
                    ret = execShell(cmd)
                    if 'd' in ret.keys():
                        logging.info('push vdexExtractor success')
                    cmd = self._adb + ' shell "su -c \' chmod +x /data/local/tmp/'+vdextool+' \' " '
                    ret = execShell(cmd)

        #android6未处理odex，需要framework/baksmali

        for p in pkgs:
            logging.info('=='+p)
            sp = self._dirapps+p
            
            needDownload = False
            needPullfromDevice = False
            
            #存在APK时，判断是否有dex、是否过期
            if os.path.isfile(sp+'.apk'):
            
                if self.isDexExist(sp+'.apk'):
                    ver = self.getVersionApk(p)
                    over = self.getVersionOnline(p)
                    dver = self.getVersionDevice(p)
                    
                    if not ver:
                        logging.error('get apk version error')
                    else:
                        #线上存在
                        if over:
                            tover = over.split(':')
                            if len(tover) == 2:
                                # 检查是否半年未更新，未维护APP直接跳过
                                lastupdate = datetime.datetime.now() - datetime.timedelta(days = 180)
                                lastupdate = lastupdate.strftime("%Y-%m-%d")
                                if lastupdate > tover[1]:
                                    logging.info('!!outdated')
                                if ver < tover[0]:
                                    os.remove(sp+'.apk')
                                    #设备是否存在最新版
                                    if dver and dver >= tover[0]:
                                        needPullfromDevice = True
                                    else:
                                        needDownload = True
                                    logging.info('old version - online')
                            
                        else:
                            if dver:
                                #切换手机时，版本可高可低
                                if ver != dver:
                                    os.remove(sp+'.apk')
                                    needPullfromDevice = True
                                    logging.info('version not same - device')
                            else:
                                #app已经不存在
                                logging.error('app package name changed')
                        
                else:
                    needPullfromDevice = True
                    os.remove(sp+'.apk')

            else:
                if p in self._devicepkg:
                    needPullfromDevice = True
                else:
                    needDownload = True

            if needPullfromDevice:
                cmd = self._adb + ' shell "pm path  '+p+'"'
                ret = execShell(cmd)
                # 可能返回多个APK
                if 'd' in ret.keys() and ret.get('d'):
                    apkpath = ret.get('d').split('\n')[0].split(':')[1]
                    logging.info('Pull from device')
                    cmd = self._adb + ' pull '+apkpath+' '+sp
                    ret = execShell(cmd)
                    if 'd' in ret.keys():
                        shutil.move(sp, sp+'.apk')
                        if not self.isDexExist(sp+'.apk') and self._androidver >= '7':
                            self.assembleAPP(apkpath, sp, vdextool, cdextool)
                    else:
                        logging.error('pull error'+ret.get('e')+apkpath)
                else:
                    logging.error('device has no '+p)
            if needDownload:
                #下载
                url = packageinfo_get_getpkg(p, False)
                if url :
                    logging.info('Downloading ')
                    if self.downloadFile(url, sp+'.tmp'):
                        ret = shutil.move(sp+'.tmp', sp+'.apk')
                    else:
                        logging.info('Downlod error ')
                else:
                    logging.info('!!pkgname not exists')
            
        logging.info('====Download done====')

    def installPkgList(self, pkgs):
        self.downloadPkgList(pkgs)

        logging.info('======install======')

        for p in pkgs:
            logging.info('=='+p)
            if p in self._devicepkg:
                #logging.info('exists')
                continue
            
            if not os.path.isfile(self._dirapps+p+'.apk'):
                logging.error('apk file not exists')
                continue

            ret = self.suinstall(p)
            if 'd' in ret.keys():
                logging.info('Install success')
            else:
                logging.error('error install '+ret.get('e'))

        # #install monkey
        # if not self.getinstallmks():
        #     logging.error('Install mks error')
        #     return
        # installmcmd = self._adb + ' shell "su -c \' monkey -f /sdcard/install.mks 1000\'" '
        # installm = execShellDaemon(installmcmd)
        # ##

        # for p in pkgs:
        #     logging.info('=='+p)
        #     if p in self._devicepkg:
        #         #logging.info('exists')
        #         continue
            
        #     if not os.path.isfile(self._dirapps+p+'.apk'):
        #         logging.error('apk file not exists')
        #         continue

        #     if installm.poll():
        #         installm = execShellDaemon(installmcmd)
        #     logging.info('Installing ')
        #     cmd = self._adb + ' install '+self._dirapps+p+'.apk'
        #     ret = execShell(cmd)
        #     if 'e' in ret.keys():
        #         logging.error(ret.get('e'))
        #     else:
        #         logging.info('Install success')

        # #清理monkey     
        # installm.terminate()
        # time.sleep(1)
        # self.killMonkey()

        logging.info('======Install done======')

    def uninstallPkg(self, pkgs):
        for p in pkgs:
            logging.info('Uninstalling '+p)
            if p in self._devicepkg:
                # always return true
                cmd = self._adb + '  shell pm  uninstall '+p
                ret = execShell(cmd)
                if ret.get('d'):
                    logging.info('Uninstall succ')
                else:
                    logging.error('Uninstall error')
                
            else:
                logging.error("not installed ")

    def downloadFile(self, url, savepath):
        try:
            urllib.request.urlretrieve(url, savepath)
            return True
        except Exception as e:
            logging.info(str(e))
            return False

    def assembleAPP(self, path, sp, vdextool, cdextool):
        d = os.path.dirname(path)
        n = os.path.basename(d)+'.vdex'
        dt = d+'/oat/arm/'+n
        cmd = self._adb + ' shell "ls  '+d+'/oat/arm/'+n+' "'
        ret = execShell(cmd)
        if 'No such file' in str(ret) :
            cmd = self._adb + ' shell "ls  '+d+'/oat/arm64/'+n+' "'
            ret1 = execShell(cmd)
            if 'No such file' not in str(ret1):
                dt = d+'/oat/arm64/'+n
            else:
                logging.error('dex and vdex not exist')
                return
        
        #在手机上转换，跨平台
        logging.info('using vdexExtractor')
        cmd = self._adb + ' shell  "mkdir /data/local/tmp/appstarter"'
        ret = execShell(cmd)
        cmd = self._adb + ' shell  "/data/local/tmp/'+vdextool+'  -f -i  '+dt+' -o /data/local/tmp/appstarter/"'
        ret = execShell(cmd)

        # multi cdex?
        cmd = self._adb + ' shell "ls /data/local/tmp/appstarter/'+os.path.basename(d)+'_classes*.cdex | wc"'
        ret = execShell(cmd)
        count = 0
        if 'd' in ret.keys():
            count = int(ret.get('d').rstrip('\n').split()[0])
        cdex = False
        for i in range(0, count):
            #cdex
            cdex = True
            logging.info('using compact-dex-converter')
            t = str(i + 1)
            if t == '1':
                t = ''
            cmd = self._adb + ' shell  "/data/local/tmp/'+cdextool+' /data/local/tmp/appstarter/'+os.path.basename(d)+'_classes'+t+'.cdex"'
            ret = execShell(cmd)

        if count == 0:
            #no cdex
            cmd = self._adb + ' shell "ls /data/local/tmp/appstarter/'+os.path.basename(d)+'_classes*.dex"'
            ret = execShell(cmd)
            if 'No such file' in str(ret):
                logging.error('vdex to dex/cdex error')

        cmd = self._adb + ' pull  /data/local/tmp/appstarter/ '+self._dirappstmp
        ret = execShell(cmd)
        cmd = self._adb + ' shell  "rm -f  /data/local/tmp/appstarter/* "'
        ret = execShell(cmd)

        # cdex = False
        # for f in os.listdir(self._dirappstmp+'appstarter'):
        #     if os.path.basename(d)+'_classes' in f and '.cdex' in f:
        #         cdex = True                
        #         # cdex to dex 在PC上转换
        #         if platform.system() == 'Linux' and os.path.isfile(self._dirinter+'compact_dex_converters'):
        #             logging.info('using compact_dex_converters')
        #             cmd = self._dirinter+'compact_dex_converters  '+os.path.join(self._dirappstmp+'appstarter', f)
        #             ret = execShell(cmd)
        #         else:
        #             logging.error('use linux to covert cdex')
        # if not cdex:
        #     logging.error('vdex to cdex error')

        zipf = zipfile.ZipFile(sp+'.apk', 'a')
        #多个dex
        ndex = False
        for f in os.listdir(self._dirappstmp+'appstarter'):
            if cdex and '.new' in f and os.path.basename(d)+'_classes' in f:
                # com.miui.fm_classes.cdex.new
                zipf.write(os.path.join(self._dirappstmp+'appstarter', f), f.split('_')[1].split('.')[0]+'.dex')
                ndex = True

            elif not cdex and '.dex' in f and os.path.basename(d)+'_classes' in f:
                # com.miui.fm_classes.dex
                zipf.write(os.path.join(self._dirappstmp+'appstarter', f), f.split('_')[1])
        zipf.close()
        if not ndex and cdex:
            logging.error('cdex to dex error')
        logging.info('assemble apk done')
        shutil.rmtree(self._dirappstmp+'appstarter')

        # # pull vdex, 在PC上转换
        # cmd = self._adb + ' pull '+dt+' '+sp+'.vdex'
        # ret = execShell(cmd)
        # if os.path.isfile(sp+'.vdex'):
        #     # android pie 9, multi dex
        #     # convert to cdex
        #     cmd = self._dirinter+'vdexExtractor  -f  -i '+sp+'.vdex '+' -o '+self._dirappstmp
        #     ret = execShell(cmd)
        #     pkg = os.path.basename(sp)
        #     cdex = False
        #     for f in os.listdir(self._dirappstmp):
        #         if pkg+'_classes' in f and '.cdex' in f:
        #             cdex = True
        #             # cdex to dex
        #             cmd = self._dirinter+'compact_dex_converters  '+self._dirappstmp+f
        #             ret = execShell(cmd)

        #     zipf = zipfile.ZipFile(sp+'.apk', 'a')
        #     for f in os.listdir(self._dirappstmp):
        #         if cdex and '.new' in f and pkg+'_classes' in f:
        #             # com.miui.fm_classes.cdex.new
        #             zipf.write(self._dirappstmp+f, f.split('_')[1].split('.')[0]+'.dex')

        #         elif not cdex and '.dex' in f and pkg+'_classes' in f:
        #             # com.miui.fm_classes.dex
        #             zipf.write(self._dirappstmp+f, f.split('_')[1])
        #     zipf.close()

        #     os.remove(sp+'.vdex')
        #     for f in os.listdir(self._dirappstmp):
        #         os.remove(self._dirappstmp+f)
            
        # else:
        #     logging.error('dex and vdex not exist')

    def killMonkey(self):
        logging.info('Clean monkey')
        cmd = self._adb + ' shell "ps -A | grep com.android.commands.monkey" '
        ret = execShell(cmd)
        if 'd' in ret.keys():
            data = ret.get('d').split('\n')
            for d in data:
                tmp = d.split()
                if len(tmp) == 9 and tmp[8] == 'com.android.commands.monkey':
                    cmd = self._adb + ' shell "su -c \' kill -9 '+tmp[1]+'\' "'
                    ret = execShell(cmd)
                    if 'e' in ret.keys():
                        logging.info(ret.get('e'))

        logging.info('Clean monkey done')

    def suinstall(self, pkg):
        path = '/data/local/tmp/'+pkg+'.apk'
        cmd = self._adb+' push '+self._dirapps+pkg+'.apk '+path
        execShell(cmd)
        cmd = self._adb+' shell "su -c \'pm install '+path+' \'"'
        ret = execShell(cmd)
        cmd = self._adb+' shell "rm '+path+'"'
        execShell(cmd)
        return ret

    def getinstallmks(self):
        #部分机型adb安装app需要手动确认
        out = '''
        count=100
        speed=1.0
        start data >>

        DispatchPointer(10000, 10000, 0, xpoint, ypoint, 0, 0, 0, 0, 0, 0, 0)
        DispatchPointer(10000, 10000, 1, xpoint, ypoint, 0, 0, 0, 0, 0, 0, 0)
        UserWait(7000)
        '''
        ret = execShell(self._adb+' shell wm size')
        if 'e' in ret.keys():
            logging.error(ret.get('e'))
            return False
        #Physical size: 1080x1920
        tmp = ret.get('d')
        tmp = tmp.split(': ')
        tmp = tmp[1]
        tmp = tmp.split('x')
        width = int(tmp[0])
        height = int(tmp[1])
        out = out.replace('xpoint', str(int(width/4)))
        out = out.replace('ypoint', str(height - 150))
        
        ret = execShell(self._adb+' shell "echo \' '+out+'\' >/sdcard/install.mks"')
        if 'e' in ret.keys():
            logging.error(ret.get('e'))
            return False

        return True

    def getPermissionPid(self):
        # miui部分机型适用
        p = 'com.lbe.security.miui:ui'
        tpcmd = self._adb + ' shell "ps -A | grep '+p+'" '
        ret = execShell(tpcmd)
        if 'd' in ret.keys():
            data = ret.get('d').split('\n')
            for d in data:
                tmp = d.split()
                if len(tmp) == 9 and tmp[8] == p:
                    return tmp[1]
        return ''


##########end AppStarter#########

def getPkgListInternet(pkg):
    return packageinfo_get_getpkg(pkg, True)

def getPkgList(pkg):
    #包名或文件名
    if os.path.isfile(pkg):
        try:
            with open(pkg, 'r') as f:
                pkgs = f.read().split('\n')
        except Exception as e:
            logging.info(str(e))
            pkgs = []
    elif pkg:
        pkgs = pkg.split(',')
    out = []
    for p in pkgs:
        if p:
            out.append(p.strip())
    return out

def getExport(pkg):
    p = []
    apps = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'apps', '')
    if os.path.isfile(pkg) and '.apk' in pkg:
        p.append(pkg)
    elif os.path.isfile(apps+pkg+'.apk'):
        p.append(apps+pkg+'.apk')
    elif os.path.isfile(pkg):
        pp = getPkgList(pkg)
        for t in pp:
            p.append(apps+t+'.apk')
    else:
        logging.error('pkg input error')

    for pp in p:
        try:
            from inter.apkcookpy.lib.apk import APKCook
            APKCook(pp).show()
        except:
            logging.error('=error '+pp)



if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Android APP analyze tool', formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog='''eg:(pkglist.txt one packgae name per line)
    python appstarter.py -m pkglist.txt               batch monkey test
    python appstarter.py -m com.xiaomi.smarthome 
    python appstarter.py -m 'com.xiaomi.smarthome, com.xiaomi.youpin'  
    python appstarter.py -m -a pkglist.txt             start non-exported component with root

    python appstarter.py -i pkglist.txt -s e46bc20a           test with device e46bc20a

    python appstarter.py -i pkglist.txt   install
    python appstarter.py -i com.xiaomi.smarthome  

    python appstarter.py -e com.xiaomi.smarthome          get apk exported component
    python appstarter.py -e /path/to/smarthome.apk  
    python appstarter.py -e pkglist.txt 

    python appstarter.py -l com.xiaomi.smarthome        search apps relative
    python appstarter.py -l com.xiaomi
    ''')
    parser.add_argument("-m", "--monkey", type=str, help="monkey test")
    parser.add_argument("-a", "--startall", action="store_true", help="start all component")
    parser.add_argument("-i", "--install", type=str, help="batch install")
    parser.add_argument("-u", "--uninstall", type=str, help="batch uninstall")
    parser.add_argument("-d", "--download", type=str, help="batch download")
    parser.add_argument("-s", "--deviceid", type=str, help="device id")
    parser.add_argument("-c", "--clean", action="store_true", help="clean")
    parser.add_argument("-e", "--export", type=str, help="get apk exported components")
    parser.add_argument("-l", "--lists", type=str, help="search apps relative")    

    if sys.version_info.major != 3:
        print('Run with python3')
        sys.exit()
    # if platform.system() != 'Linux':
    #     print('work better with linux')

    args = parser.parse_args()
    monkey = args.monkey
    startall = args.startall
    install = args.install
    uninstall = args.uninstall
    lists = args.lists
    download = args.download
    deviceid = args.deviceid
    clean = args.clean
    export = args.export


    try:
        if monkey:
            appstarter = AppStarter(deviceid)
            appstarter.monkey(monkey, startall)
        
        elif install:
            appstarter = AppStarter(deviceid)
            appstarter.installPkgList(getPkgList(install))

        elif uninstall:
            appstarter = AppStarter(deviceid)
            appstarter.uninstallPkg(getPkgList(uninstall))

        elif download:
            appstarter = AppStarter(deviceid)
            appstarter.downloadPkgList(getPkgList(download))

        elif clean:
            appstarter = AppStarter(deviceid)
            appstarter.killMonkey()
        
        elif export:
            getExport(export)

        elif lists:
            print(getPkgListInternet(lists))

        else:
            parser.print_help()
    except KeyboardInterrupt:
        logging.info('Ctrl+C')
        if appstarter:
            appstarter.killMonkey()