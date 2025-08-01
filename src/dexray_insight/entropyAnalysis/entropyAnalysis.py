import zipfile
#from shannon_entropy import shannon_entropy
import numpy as np
from scipy.stats import entropy

high_Entropy_Files = []

def analyseEntropy(apk_path):
    #apk = apkutils.APK.from_file(apk_path) #list all content from apk file

    with zipfile.ZipFile(apk_path,'r') as apk:

        #get all files from the apk
        for file in apk.namelist():
            print (file)

            #open and read the files
            try:
                with apk.open(file) as f:
                    data = f.read()

                #calculate entropy
                count = np.bincount(list(data), minlength=256)
                prob = count/len(data)
                shannon_entropy = entropy(prob, base=2)

                #print(shannon_entropy) #debug and testing

                if shannon_entropy  >= 7:
                    high_Entropy_Files.append(file)

            except Exception as e:
                print("could not open file: " + file)
                print(e)

    print(high_Entropy_Files)
    return high_Entropy_Files

def print_results():
    print(high_Entropy_Files)



