from sklearn import svm
clf = svm.SVC(decision_function_shape='ovo', verbose=True, gamma='scale', kernel='linear', probability=False)