import os

os.system('git log -1 --pretty=format:"%h" > .git/CUR_COMMIT')
os.system('zip -j submit.zip \
          .git/CUR_COMMIT \
          foggytcp/src/foggy_function.cc \
          foggytcp/src/foggy_tcp.cc \
          foggytcp/inc/foggy_function.h \
          foggytcp/inc/foggy_tcp.h')
