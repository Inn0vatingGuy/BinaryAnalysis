import argparse
import r2
import sys
import r2pipe
import json
import os 
import time 

vulnFunc=['RtlCopyMemory','strncpy','strlen','memcpy','gets','puts','memset','strcpy']

class Analysis:

    NoOfVulnFilesFound=0
    NoOfVulnFunctionsFound=0
    

    def __init__(self):
        self.OutPutDirname=''
        self.path_to_binary=''
        self.OutPutDirname=''
        self.basePath = ''
        
    def output_dirname(self):
        return self.OutPutDirname
        
    def get_output_dirname(self):
        return self.OutPutDirname
        
        
    def set_output_dirname(self,OutPutDirname):
        self.OutPutDirname= OutPutDirname
    
    def set_path_to_binary(self,path_to_binary):
        self.path_to_binary = path_to_binary

        
    def get_path_to_binary(self):
        return self.path_to_binary
    
    def set_basePath(self,basePath):
        self.basePath=basePath
        
    def get_basePath(self):
        return self.basePath    
    
    def set_output_dir(self):
        x=os.getcwd()
        dirName=time.ctime()
        dirName=dirName.replace(" ","_")
        dirName=dirName.replace(":","_")
        dirName=x+'/'+'Output'+'_'+str(os.path.basename(self.get_path_to_binary()).replace(".","_"))+'_'+dirName
        os.mkdir(dirName)
        self.set_output_dirname(dirName)
        return dirName

        
    def findBannedAPIs(self, path,vulnFunctionsOutput):
        print("Analysing binary for Banned APIs/Functions : "+str(path))
        
        default_plugins=["-e","bin.cache=true"]
        r2=r2pipe.open(path)#,default_plugins)
        r2.cmd("r2 -e bin.cache=true")
        r2.cmd('aaa 2> /dev/null')
        x=r2.cmd('aflj')
        json_out= json.loads(x)
        xref_adress =0x1
        
        print("filename is "+ str(vulnFunctionsOutput))
        filehandle=open(vulnFunctionsOutput,'a')
        filehandle.write('Binary Name '+str(path))
        for i in vulnFunc:
            
            #print("checking for function "+str(i))
            time.sleep(1)
            for j in json_out:
                #print("Value in json "+str(j['name']))
                if i in j['name']:
                    print("found function "+str(i)+" "+str(j['codexrefs']))
                    #sleep(5)
                   # print("function name "+str(i))
                    if 'codexrefs' not in j:
                        print("Xref not found!")
                        continue
                   
                    
                    self.NoOfVulnFilesFound = self.NoOfVulnFilesFound +1                  
                    self.NoOfVulnFunctionsFound=self.NoOfVulnFunctionsFound + len(j['codexrefs'])
                
                    for k in j['codexrefs']:
                       
                        os.system("echo '\n============================================================= \n' >> "+vulnFunctionsOutput)
                        xref_address = hex(k['addr'])
                        called_address = hex(k['at'])
                        xref_info=r2.cmd('pD 30 @'+str(xref_address))
                        filehandle.write('\n'+'Insecure API "'+str(i)+'" found')
                        filehandle.write('\n'+'Function Address in Binary '+str(xref_address)+' ')
                        filehandle.write('\n'+'Referenced at Address '+str(called_address))
                        filehandle.write('\n'+str(xref_info))
                        print("Xref Address "+str(xref_info))	
                 
        filehandle.close()        

    def iterateDir(self,path,vulnFunctionsOutput):
        dirname=os.path.split(path)[0]
        os.chdir(path)
        print("osdir "+os.getcwd())
        filehandle=open(vulnFunctionsOutput,'a')
        filehandle.write('Dir Name '+str(self.get_basePath()))
        filehandle.close()
        for dirpath, dirs, files in os.walk("."):
            for filename in files:
                fname=os.path.join(dirpath,filename)
                #with open(fname,'rb') as myfile:
                try:
                   fileInDir = open(fname,'rb')
                   buffer = fileInDir.read(4)
                   
                   if b'ELF' in buffer:
                      print("ELF binary")
                   else :
                      print("Not an ELF binary "+str(fname))
                      continue
                
                   print("File being worked on "+str(fname))
                   self.findBannedAPIs(fname,vulnFunctionsOutput)
                     
                except Exception as e :
                   pass 
                   print(e)


def startHunt(path):
    print("in StartHunt")
    ai=Analysis()
    ai.set_path_to_binary(path)
    currentDir=os.getcwd()
    ai.set_output_dir()
    vulnFunctionsOutput = ai.get_output_dirname()+'/'+'VulnFunctionsFile'
    ai.set_basePath(path)
    #ai.basePath = path
    ai.iterateDir(path,vulnFunctionsOutput)

    #ai.findBannedAPIs(path)
import getopt



def main(argv):
   specificFile = ''
   directory = ''
   try:
      opts, args = getopt.getopt(argv,"hd:of:",["ifile="])
   except getopt.GetoptError:
    
      sys.exit(2)
  
   if len(argv) < 2:
      print("Missing argument , use -h ")
   
   for opt, arg in opts:
      if opt == '-h':
         print ('FindBannedAPIs.py -d <path to directory with binaries to analyse>')
         sys.exit()
      elif opt in ("-d", "--dir"):
         directory = arg
         startHunt(directory)
         print("directory with binaries to scan "+str(directory))
      elif opt in ("-f", "--file"):
         specificFile = arg
         print("FIle to scan "+str(specificFile))


if __name__ == "__main__":
   main(sys.argv[1:])     

    