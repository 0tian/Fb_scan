# -*- coding: UTF-8 -*-

'''
@author:banxia
@time:2019-6-20
'''


'''
https://mp.weixin.qq.com/s/lMOieL_RFRHsh5OW4G4axg
https://yq.aliyun.com/articles/596595
https://mp.weixin.qq.com/s/lMOieL_RFRHsh5OW4G4axg
'''

import os
import subprocess
from beeprint import pp
import fire
from bs4 import BeautifulSoup
import datetime



class Chan:
    
    def __init__(self,proxy='',select=None):
        self._proxy = proxy
        self._select = select



    def start(self,url):
        if self._select== None:
            Os_operation.file_rm(url)
        Os_operation.mkdir('intelligence/%s'%url)
        Os_operation.mkdir('intelligence/{}/{}'.format(url,Os_operation.return_time()))

    def attack(self,url):
        
        self.start(url)
        
        shells=[
        '{0} theharvester -d {1} -l 150  -b all -f intelligence/{1}/{1}.html'.format(self._proxy,url),
        'cd teemo && {0} python2 teemo.py -d {1} -o  ../../intelligence/{1}/teemo_{1}.txt '.format(self._proxy,url),
        'cd subDomainsBrute &&  python2 subDomainsBrute.py  {1}   --process=8 --full -o ../intelligence/{1}/subbrute_{1}.txt '.format(self._proxy,url),]
        #'cd Sublist3r && {0} python3 sublist3r.py -d {1} -t 25 -v  -o ../intelligence/{1}/3r_{1}.txt '.format(self._proxy,url),]
        
        if self._proxy != 'proxychains':
            shells[0] = '{0} theharvester -d {1} -l 150   -b baidu -f intelligence/{1}/{1}.html'.format(self._proxy,url)
            #shells[2] = "'cd Sublist3r && python3 sublist3r.py -d {0} -t 13 -v -e baidu,yahoo,bing,ask,ssl,dnsdumpster  -o ../intelligence/{0}/3r_{0}.txt '.format(url,)"
        
        if self._select== None:
            for shell in shells:
                subprocess.run(shell,shell=True)
            
        else:
            for number in self._select:
                subprocess.run(shells[number],shell=True)


        
        self.ending(url)
        return

    def ending(self,url):

        Os_operation.the_data(url)
        Os_operation.clean(url)
        Os_operation.set_data(url)
        pp('完成收集')
        #self.ip_scan(url)
        #self.whatweb(url)


    def scan(self,*urls):
        
        Os_operation.mkdir()
        if self._proxy==True:
            self._proxy = 'proxychains'

        for url in urls:
            self.attack(url) 
        return
    
    def ip_scan(self,url):
        path = "intelligence/{0}/{1}".format(url,Os_operation.return_time())
        shell ="cd {} && sudo nmap -sS -Pn -T4 -iL ips  -oN namp_ip.txt".format(path)
        subprocess.run(shell,shell=True)

    def whatweb(self,url):
        # whatweb
        log_path = os.path.split(os.path.realpath(__file__))[0]+'/intelligence/'+url+'/{}/'.format(str(Os_operation.return_time()))+'whatweb_domain'
        dict_path = os.path.split(os.path.realpath(__file__))[0]+'/intelligence/'+url+'/{}/'.format(str(Os_operation.return_time()))+'/domain'
    
        shell = "whatweb  -a 3 -i {} --log-brief='{}' ".format(dict_path,log_path)
        subprocess.run(shell,shell=True)


class Os_operation:

    @classmethod
    def mkdir(cls,path="intelligence"):
        #初始化intelligence目录，用于集合渗透情报
         if not os.path.isdir(path) :
             os.makedirs(path)
             pp('创建%s目录'%path)

    @classmethod
    def the_data(cls,url=''):
        #用于处理theharvester的生成文件
        path = "intelligence/{0}/{0}.html".format(url)
        
        try:

            with open(path,'r',encoding='utf-8') as f:
                soup = BeautifulSoup(f.read(),'lxml')
                
            with open("intelligence/{0}/the_{0}.txt".format(url),"a+") as r:
                for data in soup.find_all('li'):
                    r.writelines(data.get_text()+'\r\n')
            subprocess.run('rm %s'%path,shell=True)
        
        except:
            pp('文件不存在：%s'%path)

    @classmethod
    def file_rm(cls,url):
        
        path = "intelligence/{0}".format(url)
        if not os.path.isdir(path):
            return
        shell = "cd {} && rm -rf *.txt && rm -rf tee*.csv  && rm -rf *.xml && rm -rf *.html".format(path)
        subprocess.run(shell,shell=True)
        pp('清除临时文件')
  
    @classmethod
    def return_time(cls):
        year = datetime.datetime.now().year
        month =datetime.datetime.now().month
        day = datetime.datetime.now().day
        time = str(year)+str(month)+str(day)
        return time

    @classmethod
    def set_data(cls,url):
        # 用于文本去重,此时结果文件在时间目录
        path = "intelligence/{0}/{1}".format(url,Os_operation.return_time())
        ip_path = "intelligence/{0}/ip.txt".format(url)
        domain_path  = "intelligence/{0}/domain.txt".format(url)
        mail_path  = "intelligence/{0}/mail.txt".format(url)

        try:

            with open(ip_path,'r',encoding='utf-8') as ip_file:

                ips =ip_file.readlines()
                
                for i in set(ips):
                    shell = "cd {} && ipcalc -n {}/28 |grep Network |awk '{{print ($2)}}'>>ips".format(path,i.replace('\n',''))
                    subprocess.run(shell,shell=True)        
        except:
            pp('ip_path文件不存在')

        try:

            with open(domain_path,'r',encoding='utf-8') as domain_file:
                
                domians =domain_file.readlines()
                for i in set(domians):
                    shell = " cd {} && echo {} >>  domain".format(path,i.replace('\n',''))
                    subprocess.run(shell,shell=True)  
        except:
            pp('domain_path文件不存在')
        
        try:

            with open(mail_path,'r',encoding='utf-8') as mail_file:
                mails =mail_file.readlines()
                for i in set(mails):
                    shell = " cd {} && echo {} >>  mail".format(path,i.replace('\n','').replace("'",""))
                    subprocess.run(shell,shell=True)  
        except:
            pp('mail_path文件不存在')

    @classmethod
    def clean(cls,url):
        #用于提取生成文本信息
        path = "intelligence/{0}/".format(url)
        domain_shell =[
            #"cd {} && cat 3r*.txt >> domain.txt".format(path),
            "cd {} && cat the*.txt |grep -v @|awk -F ':' '{{print($1)}}' >> domain.txt".format(path),
            "cd {} && cat sub*.txt |awk '{{print($1)}}' >> domain.txt".format(path),
            "cd {} && cat tee*.txt |grep -v @|grep -v ^[0-9]|grep -E -v '.{{50,}}' >> domain.txt".format(path),


        ]
        for shell in domain_shell:
            subprocess.run(shell,shell=True)

        mail_shell =[
            "cd {} && cat the*.txt  teemo*.txt |grep @>>mail.txt ".format(path)
        ]

        for shell in mail_shell:
            subprocess.run(shell,shell=True)

        ip_shell = [
            "cd {} && cat sub*.txt |awk '{{print($2)}}' >> ip.txt".format(path),
            "cd {} && cat the*.txt |grep -v @ |awk -F ':' '{{print($2)}}' >> ip.txt".format(path),
            "cd {} && cat teemo*.txt |grep ^[0-9]|sed 's6/.*66g' >> ip.txt".format(path)

        ]

        for shell in ip_shell:
            subprocess.run(shell,shell=True)

   
def whatweb(url):
    # whatweb
    log_path = os.path.split(os.path.realpath(__file__))[0]+'/intelligence/'+url+'/{}/'.format(str(Os_operation.return_time()))+'whatweb_domain'
    dict_path = os.path.split(os.path.realpath(__file__))[0]+'/intelligence/'+url+'/{}/'.format(str(Os_operation.return_time()))+'/domain'
    
    shell = "whatweb  -a 3 -i {} --log-brief='{}' ".format(dict_path,log_path)
    print(shell)
    subprocess.run(shell,shell=True)

    
if __name__ == '__main__':
   fire.Fire(Chan) 
