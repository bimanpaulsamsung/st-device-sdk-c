import json
import re
import sys
Read_File = open(sys.argv[1],"r")
config_dict={}
config_dict.update(name= "stdk")
main_dict={}
fields =['macro_name', 'value']
for lines in Read_File:
     dict1={}
     dict2={}
     each_line =((lines.strip().split("=")))
     subs_line=(lines.strip().lower().replace("_","-").replace("config-stdk-iot-","").replace("config-","").split("="))
     if ((each_line[-1]== "y") and len(each_line) > 1) :
          each_line[-1]=bool("true")
     elif (type(each_line[-1]== int) and len(each_line) > 1) :
          each_line[-1]=int(each_line[-1])
     else :
          continue
     dict1[fields[0]]=each_line[0]
     dict2[fields[1]]=each_line[-1]
     dict1.update(dict2)
     j=subs_line[-2]
     main_dict[j]=dict1
     config_dict["config"]=main_dict 
final_json=open(sys.argv[2],"w")
json.dump(config_dict,final_json,indent=8)
final_json.close()
