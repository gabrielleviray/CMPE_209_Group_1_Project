import pandas as pd
import numpy as np
import sys
from sklearn.model_selection import train_test_split
from sklearn.feature_selection import mutual_info_classif

def kddDfEncode(kdd):

	kddFourClasses = kdd.copy()
	dos   = ['neptune.', 'land.', 'pod.', 'smurf.', 'teardrop.', 'back.', 'worm.', 'udpstorm.', 'processtable.', 'apache2.']
	probe = ['ipsweep.','satan.','nmap.','portsweep.','mscan.','saint.']
	R2L   = ['ftp_write.','guess_passwd.', 'imap.','multihop.','phf.'
			 ,'spy.','warezclient.','warezmaster.','snmpguess.','named.','xlock.','snmpgetattack.','httptunnel.','sendmail.']
	U2R   = ['buffer_overflow.','loadmodule.','perl.','rootkit.','ps.','xterm.','sqlattack.']

	kddFourClasses['attack_type'].values[kddFourClasses['attack_type'].isin(dos)] = 'dos'
	kddFourClasses['attack_type'].values[kddFourClasses['attack_type'].isin(probe)] = 'probe'
	kddFourClasses['attack_type'].values[kddFourClasses['attack_type'].isin(R2L)] = 'R2L'
	kddFourClasses['attack_type'].values[kddFourClasses['attack_type'].isin(U2R)] = 'U2R'

	kddFourClassesEncoded = pd.get_dummies(kddFourClasses, columns=['protocol_type','flag','service'])
	#move the attack_type column to the end
	attackType = kddFourClassesEncoded.pop('attack_type')
	kddFourClassesEncoded['attack_type'] = attackType
	
	return kddFourClassesEncoded

def saveList(df):
    df.to_csv('data_analytics/kddPearsonList.csv', columns=None, header=True, index=True)
    print('Data saved to data_analytics/kddPearsonList.csv')



def kddPearsonCorr(df):
    X_train,X_test,y_train,y_test=train_test_split(df.drop(labels=['attack_type'], axis=1),
    df['attack_type'],
    test_size=0.3,
    random_state=42)
    
    mutual_info = mutual_info_classif(X_train, y_train)
    
    pd.set_option('display.max_rows', None)
    mutual_info = pd.Series(mutual_info)
    mutual_info.index = X_train.columns
    
    saveList(mutual_info.sort_values(ascending=False))
    return mutual_info.sort_values(ascending=False)

def retainFeatures(df,a):

    kddPearsonCorrList = pd.read_csv('data_analytics/kddPearsonList.csv', index_col=0)
    final_columns = kddPearsonCorrList.head(a).index
    return df.drop(columns=kddPearsonCorrList.index.difference(final_columns))



