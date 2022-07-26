import re
from idc import *
from idaapi import *
from idautils import *

def writeCmt(addrList,syscallNum):
    i=0
    while i < len(addrList):
        if syscallNum[i]==0:
                idc.set_cmt(addrList[i]+2,"syscall: restart_syscall",0)
        elif syscallNum[i]==1:
                idc.set_cmt(addrList[i]+2,"syscall: exit",0)
        elif syscallNum[i]==2:
                idc.set_cmt(addrList[i]+2,"syscall: fork",0)
        elif syscallNum[i]==3:
                idc.set_cmt(addrList[i]+2,"syscall: read",0)
        elif syscallNum[i]==4:
                idc.set_cmt(addrList[i]+2,"syscall: write",0)
        elif syscallNum[i]==5:
                idc.set_cmt(addrList[i]+2,"syscall: open",0)
        elif syscallNum[i]==6:
                idc.set_cmt(addrList[i]+2,"syscall: close",0)
        elif syscallNum[i]==7:
                idc.set_cmt(addrList[i]+2,"syscall: not implemented",0)
        elif syscallNum[i]==8:
                idc.set_cmt(addrList[i]+2,"syscall: creat",0)
        elif syscallNum[i]==9:
                idc.set_cmt(addrList[i]+2,"syscall: link",0)
        elif syscallNum[i]==10:
                idc.set_cmt(addrList[i]+2,"syscall: unlink",0)
        elif syscallNum[i]==11:
                idc.set_cmt(addrList[i]+2,"syscall: execve",0)
        elif syscallNum[i]==12:
                idc.set_cmt(addrList[i]+2,"syscall: chdir",0)
        elif syscallNum[i]==13:
                idc.set_cmt(addrList[i]+2,"syscall: not implemented",0)
        elif syscallNum[i]==14:
                idc.set_cmt(addrList[i]+2,"syscall: mknod",0)
        elif syscallNum[i]==15:
                idc.set_cmt(addrList[i]+2,"syscall: chmod",0)
        elif syscallNum[i]==16:
                idc.set_cmt(addrList[i]+2,"syscall: lchown",0)
        elif syscallNum[i]==17:
                idc.set_cmt(addrList[i]+2,"syscall: not implemented",0)
        elif syscallNum[i]==18:
                idc.set_cmt(addrList[i]+2,"syscall: not implemented",0)
        elif syscallNum[i]==19:
                idc.set_cmt(addrList[i]+2,"syscall: lseek",0)
        elif syscallNum[i]==20:
                idc.set_cmt(addrList[i]+2,"syscall: getpid",0)
        elif syscallNum[i]==21:
                idc.set_cmt(addrList[i]+2,"syscall: mount",0)
        elif syscallNum[i]==22:
                idc.set_cmt(addrList[i]+2,"syscall: not implemented",0)
        elif syscallNum[i]==23:
                idc.set_cmt(addrList[i]+2,"syscall: setuid",0)
        elif syscallNum[i]==24:
                idc.set_cmt(addrList[i]+2,"syscall: getuid",0)
        elif syscallNum[i]==25:
                idc.set_cmt(addrList[i]+2,"syscall: not implemented",0)
        elif syscallNum[i]==26:
                idc.set_cmt(addrList[i]+2,"syscall: ptrace",0)
        elif syscallNum[i]==27:
                idc.set_cmt(addrList[i]+2,"syscall: not implemented",0)
        elif syscallNum[i]==28:
                idc.set_cmt(addrList[i]+2,"syscall: not implemented",0)
        elif syscallNum[i]==29:
                idc.set_cmt(addrList[i]+2,"syscall: pause",0)
        elif syscallNum[i]==30:
                idc.set_cmt(addrList[i]+2,"syscall: not implemented",0)
        elif syscallNum[i]==31:
                idc.set_cmt(addrList[i]+2,"syscall: not implemented",0)
        elif syscallNum[i]==32:
                idc.set_cmt(addrList[i]+2,"syscall: not implemented",0)
        elif syscallNum[i]==33:
                idc.set_cmt(addrList[i]+2,"syscall: access",0)
        elif syscallNum[i]==34:
                idc.set_cmt(addrList[i]+2,"syscall: nice",0)
        elif syscallNum[i]==35:
                idc.set_cmt(addrList[i]+2,"syscall: not implemented",0)
        elif syscallNum[i]==36:
                idc.set_cmt(addrList[i]+2,"syscall: sync",0)
        elif syscallNum[i]==37:
                idc.set_cmt(addrList[i]+2,"syscall: kill",0)
        elif syscallNum[i]==38:
                idc.set_cmt(addrList[i]+2,"syscall: rename",0)
        elif syscallNum[i]==39:
                idc.set_cmt(addrList[i]+2,"syscall: mkdir",0)
        elif syscallNum[i]==40:
                idc.set_cmt(addrList[i]+2,"syscall: rmdir",0)
        elif syscallNum[i]==41:
                idc.set_cmt(addrList[i]+2,"syscall: dup",0)
        elif syscallNum[i]==42:
                idc.set_cmt(addrList[i]+2,"syscall: pipe",0)
        elif syscallNum[i]==43:
                idc.set_cmt(addrList[i]+2,"syscall: times",0)
        elif syscallNum[i]==44:
                idc.set_cmt(addrList[i]+2,"syscall: not implemented",0)
        elif syscallNum[i]==45:
                idc.set_cmt(addrList[i]+2,"syscall: brk",0)
        elif syscallNum[i]==46:
                idc.set_cmt(addrList[i]+2,"syscall: setgid",0)
        elif syscallNum[i]==47:
                idc.set_cmt(addrList[i]+2,"syscall: getgid",0)
        elif syscallNum[i]==48:
                idc.set_cmt(addrList[i]+2,"syscall: not implemented",0)
        elif syscallNum[i]==49:
                idc.set_cmt(addrList[i]+2,"syscall: geteuid",0)
        elif syscallNum[i]==50:
                idc.set_cmt(addrList[i]+2,"syscall: getegid",0)
        elif syscallNum[i]==51:
                idc.set_cmt(addrList[i]+2,"syscall: acct",0)
        elif syscallNum[i]==52:
                idc.set_cmt(addrList[i]+2,"syscall: umount2",0)
        elif syscallNum[i]==53:
                idc.set_cmt(addrList[i]+2,"syscall: not implemented",0)
        elif syscallNum[i]==54:
                idc.set_cmt(addrList[i]+2,"syscall: ioctl",0)
        elif syscallNum[i]==55:
                idc.set_cmt(addrList[i]+2,"syscall: fcntl",0)
        elif syscallNum[i]==56:
                idc.set_cmt(addrList[i]+2,"syscall: not implemented",0)
        elif syscallNum[i]==57:
                idc.set_cmt(addrList[i]+2,"syscall: setpgid",0)
        elif syscallNum[i]==58:
                idc.set_cmt(addrList[i]+2,"syscall: not implemented",0)
        elif syscallNum[i]==59:
                idc.set_cmt(addrList[i]+2,"syscall: not implemented",0)
        elif syscallNum[i]==60:
                idc.set_cmt(addrList[i]+2,"syscall: umask",0)
        elif syscallNum[i]==61:
                idc.set_cmt(addrList[i]+2,"syscall: chroot",0)
        elif syscallNum[i]==62:
                idc.set_cmt(addrList[i]+2,"syscall: ustat",0)
        elif syscallNum[i]==63:
                idc.set_cmt(addrList[i]+2,"syscall: dup2",0)
        elif syscallNum[i]==64:
                idc.set_cmt(addrList[i]+2,"syscall: getppid",0)
        elif syscallNum[i]==65:
                idc.set_cmt(addrList[i]+2,"syscall: getpgrp",0)
        elif syscallNum[i]==66:
                idc.set_cmt(addrList[i]+2,"syscall: setsid",0)
        elif syscallNum[i]==67:
                idc.set_cmt(addrList[i]+2,"syscall: sigaction",0)
        elif syscallNum[i]==68:
                idc.set_cmt(addrList[i]+2,"syscall: not implemented",0)
        elif syscallNum[i]==69:
                idc.set_cmt(addrList[i]+2,"syscall: not implemented",0)
        elif syscallNum[i]==70:
                idc.set_cmt(addrList[i]+2,"syscall: setreuid",0)
        elif syscallNum[i]==71:
                idc.set_cmt(addrList[i]+2,"syscall: setregid",0)
        elif syscallNum[i]==72:
                idc.set_cmt(addrList[i]+2,"syscall: sigsuspend",0)
        elif syscallNum[i]==73:
                idc.set_cmt(addrList[i]+2,"syscall: sigpending",0)
        elif syscallNum[i]==74:
                idc.set_cmt(addrList[i]+2,"syscall: sethostname",0)
        elif syscallNum[i]==75:
                idc.set_cmt(addrList[i]+2,"syscall: setrlimit",0)
        elif syscallNum[i]==76:
                idc.set_cmt(addrList[i]+2,"syscall: not implemented",0)
        elif syscallNum[i]==77:
                idc.set_cmt(addrList[i]+2,"syscall: getrusage",0)
        elif syscallNum[i]==78:
                idc.set_cmt(addrList[i]+2,"syscall: gettimeofday",0)
        elif syscallNum[i]==79:
                idc.set_cmt(addrList[i]+2,"syscall: settimeofday",0)
        elif syscallNum[i]==80:
                idc.set_cmt(addrList[i]+2,"syscall: getgroups",0)
        elif syscallNum[i]==81:
                idc.set_cmt(addrList[i]+2,"syscall: setgroups",0)
        elif syscallNum[i]==82:
                idc.set_cmt(addrList[i]+2,"syscall: not implemented",0)
        elif syscallNum[i]==83:
                idc.set_cmt(addrList[i]+2,"syscall: symlink",0)
        elif syscallNum[i]==84:
                idc.set_cmt(addrList[i]+2,"syscall: not implemented",0)
        elif syscallNum[i]==85:
                idc.set_cmt(addrList[i]+2,"syscall: readlink",0)
        elif syscallNum[i]==86:
                idc.set_cmt(addrList[i]+2,"syscall: uselib",0)
        elif syscallNum[i]==87:
                idc.set_cmt(addrList[i]+2,"syscall: swapon",0)
        elif syscallNum[i]==88:
                idc.set_cmt(addrList[i]+2,"syscall: reboot",0)
        elif syscallNum[i]==89:
                idc.set_cmt(addrList[i]+2,"syscall: not implemented",0)
        elif syscallNum[i]==90:
                idc.set_cmt(addrList[i]+2,"syscall: not implemented",0)
        elif syscallNum[i]==91:
                idc.set_cmt(addrList[i]+2,"syscall: munmap",0)
        elif syscallNum[i]==92:
                idc.set_cmt(addrList[i]+2,"syscall: truncate",0)
        elif syscallNum[i]==93:
                idc.set_cmt(addrList[i]+2,"syscall: ftruncate",0)
        elif syscallNum[i]==94:
                idc.set_cmt(addrList[i]+2,"syscall: fchmod",0)
        elif syscallNum[i]==95:
                idc.set_cmt(addrList[i]+2,"syscall: fchown",0)
        elif syscallNum[i]==96:
                idc.set_cmt(addrList[i]+2,"syscall: getpriority",0)
        elif syscallNum[i]==97:
                idc.set_cmt(addrList[i]+2,"syscall: setpriority",0)
        elif syscallNum[i]==98:
                idc.set_cmt(addrList[i]+2,"syscall: not implemented",0)
        elif syscallNum[i]==99:
                idc.set_cmt(addrList[i]+2,"syscall: statfs",0)
        elif syscallNum[i]==100:
                idc.set_cmt(addrList[i]+2,"syscall: fstatfs",0)
        elif syscallNum[i]==101:
                idc.set_cmt(addrList[i]+2,"syscall: not implemented",0)
        elif syscallNum[i]==102:
                idc.set_cmt(addrList[i]+2,"syscall: not implemented",0)
        elif syscallNum[i]==103:
                idc.set_cmt(addrList[i]+2,"syscall: syslog",0)
        elif syscallNum[i]==104:
                idc.set_cmt(addrList[i]+2,"syscall: setitimer",0)
        elif syscallNum[i]==105:
                idc.set_cmt(addrList[i]+2,"syscall: getitimer",0)
        elif syscallNum[i]==106:
                idc.set_cmt(addrList[i]+2,"syscall: stat",0)
        elif syscallNum[i]==107:
                idc.set_cmt(addrList[i]+2,"syscall: lstat",0)
        elif syscallNum[i]==108:
                idc.set_cmt(addrList[i]+2,"syscall: fstat",0)
        elif syscallNum[i]==109:
                idc.set_cmt(addrList[i]+2,"syscall: not implemented",0)
        elif syscallNum[i]==110:
                idc.set_cmt(addrList[i]+2,"syscall: not implemented",0)
        elif syscallNum[i]==111:
                idc.set_cmt(addrList[i]+2,"syscall: vhangup",0)
        elif syscallNum[i]==112:
                idc.set_cmt(addrList[i]+2,"syscall: not implemented",0)
        elif syscallNum[i]==113:
                idc.set_cmt(addrList[i]+2,"syscall: not implemented",0)
        elif syscallNum[i]==114:
                idc.set_cmt(addrList[i]+2,"syscall: wait4",0)
        elif syscallNum[i]==115:
                idc.set_cmt(addrList[i]+2,"syscall: swapoff",0)
        elif syscallNum[i]==116:
                idc.set_cmt(addrList[i]+2,"syscall: sysinfo",0)
        elif syscallNum[i]==117:
                idc.set_cmt(addrList[i]+2,"syscall: not implemented",0)
        elif syscallNum[i]==118:
                idc.set_cmt(addrList[i]+2,"syscall: fsync",0)
        elif syscallNum[i]==119:
                idc.set_cmt(addrList[i]+2,"syscall: sigreturn",0)
        elif syscallNum[i]==120:
                idc.set_cmt(addrList[i]+2,"syscall: clone",0)
        elif syscallNum[i]==121:
                idc.set_cmt(addrList[i]+2,"syscall: setdomainname",0)
        elif syscallNum[i]==122:
                idc.set_cmt(addrList[i]+2,"syscall: uname",0)
        elif syscallNum[i]==123:
                idc.set_cmt(addrList[i]+2,"syscall: not implemented",0)
        elif syscallNum[i]==124:
                idc.set_cmt(addrList[i]+2,"syscall: adjtimex",0)
        elif syscallNum[i]==125:
                idc.set_cmt(addrList[i]+2,"syscall: mprotect",0)
        elif syscallNum[i]==126:
                idc.set_cmt(addrList[i]+2,"syscall: sigprocmask",0)
        elif syscallNum[i]==127:
                idc.set_cmt(addrList[i]+2,"syscall: not implemented",0)
        elif syscallNum[i]==128:
                idc.set_cmt(addrList[i]+2,"syscall: init_module",0)
        elif syscallNum[i]==129:
                idc.set_cmt(addrList[i]+2,"syscall: delete_module",0)
        elif syscallNum[i]==130:
                idc.set_cmt(addrList[i]+2,"syscall: not implemented",0)
        elif syscallNum[i]==131:
                idc.set_cmt(addrList[i]+2,"syscall: quotactl",0)
        elif syscallNum[i]==132:
                idc.set_cmt(addrList[i]+2,"syscall: getpgid",0)
        elif syscallNum[i]==133:
                idc.set_cmt(addrList[i]+2,"syscall: fchdir",0)
        elif syscallNum[i]==134:
                idc.set_cmt(addrList[i]+2,"syscall: bdflush",0)
        elif syscallNum[i]==135:
                idc.set_cmt(addrList[i]+2,"syscall: sysfs",0)
        elif syscallNum[i]==136:
                idc.set_cmt(addrList[i]+2,"syscall: personality",0)
        elif syscallNum[i]==137:
                idc.set_cmt(addrList[i]+2,"syscall: not implemented",0)
        elif syscallNum[i]==138:
                idc.set_cmt(addrList[i]+2,"syscall: setfsuid",0)
        elif syscallNum[i]==139:
                idc.set_cmt(addrList[i]+2,"syscall: setfsgid",0)
        elif syscallNum[i]==140:
                idc.set_cmt(addrList[i]+2,"syscall: _llseek",0)
        elif syscallNum[i]==141:
                idc.set_cmt(addrList[i]+2,"syscall: getdents",0)
        elif syscallNum[i]==142:
                idc.set_cmt(addrList[i]+2,"syscall: _newselect",0)
        elif syscallNum[i]==143:
                idc.set_cmt(addrList[i]+2,"syscall: flock",0)
        elif syscallNum[i]==144:
                idc.set_cmt(addrList[i]+2,"syscall: msync",0)
        elif syscallNum[i]==145:
                idc.set_cmt(addrList[i]+2,"syscall: readv",0)
        elif syscallNum[i]==146:
                idc.set_cmt(addrList[i]+2,"syscall: writev",0)
        elif syscallNum[i]==147:
                idc.set_cmt(addrList[i]+2,"syscall: getsid",0)
        elif syscallNum[i]==148:
                idc.set_cmt(addrList[i]+2,"syscall: fdatasync",0)
        elif syscallNum[i]==149:
                idc.set_cmt(addrList[i]+2,"syscall: _sysctl",0)
        elif syscallNum[i]==150:
                idc.set_cmt(addrList[i]+2,"syscall: mlock",0)
        elif syscallNum[i]==151:
                idc.set_cmt(addrList[i]+2,"syscall: munlock",0)
        elif syscallNum[i]==152:
                idc.set_cmt(addrList[i]+2,"syscall: mlockall",0)
        elif syscallNum[i]==153:
                idc.set_cmt(addrList[i]+2,"syscall: munlockall",0)
        elif syscallNum[i]==154:
                idc.set_cmt(addrList[i]+2,"syscall: sched_setparam",0)
        elif syscallNum[i]==155:
                idc.set_cmt(addrList[i]+2,"syscall: sched_getparam",0)
        elif syscallNum[i]==156:
                idc.set_cmt(addrList[i]+2,"syscall: sched_setscheduler",0)
        elif syscallNum[i]==157:
                idc.set_cmt(addrList[i]+2,"syscall: sched_getscheduler",0)
        elif syscallNum[i]==158:
                idc.set_cmt(addrList[i]+2,"syscall: sched_yield",0)
        elif syscallNum[i]==159:
                idc.set_cmt(addrList[i]+2,"syscall: sched_get_priority_max",0)
        elif syscallNum[i]==160:
                idc.set_cmt(addrList[i]+2,"syscall: sched_get_priority_min",0)
        elif syscallNum[i]==161:
                idc.set_cmt(addrList[i]+2,"syscall: sched_rr_get_interval",0)
        elif syscallNum[i]==162:
                idc.set_cmt(addrList[i]+2,"syscall: nanosleep",0)
        elif syscallNum[i]==163:
                idc.set_cmt(addrList[i]+2,"syscall: mremap",0)
        elif syscallNum[i]==164:
                idc.set_cmt(addrList[i]+2,"syscall: setresuid",0)
        elif syscallNum[i]==165:
                idc.set_cmt(addrList[i]+2,"syscall: getresuid",0)
        elif syscallNum[i]==166:
                idc.set_cmt(addrList[i]+2,"syscall: not implemented",0)
        elif syscallNum[i]==167:
                idc.set_cmt(addrList[i]+2,"syscall: not implemented",0)
        elif syscallNum[i]==168:
                idc.set_cmt(addrList[i]+2,"syscall: poll",0)
        elif syscallNum[i]==169:
                idc.set_cmt(addrList[i]+2,"syscall: nfsservctl",0)
        elif syscallNum[i]==170:
                idc.set_cmt(addrList[i]+2,"syscall: setresgid",0)
        elif syscallNum[i]==171:
                idc.set_cmt(addrList[i]+2,"syscall: getresgid",0)
        elif syscallNum[i]==172:
                idc.set_cmt(addrList[i]+2,"syscall: prctl",0)
        elif syscallNum[i]==173:
                idc.set_cmt(addrList[i]+2,"syscall: rt_sigreturn",0)
        elif syscallNum[i]==174:
                idc.set_cmt(addrList[i]+2,"syscall: rt_sigaction",0)
        elif syscallNum[i]==175:
                idc.set_cmt(addrList[i]+2,"syscall: rt_sigprocmask",0)
        elif syscallNum[i]==176:
                idc.set_cmt(addrList[i]+2,"syscall: rt_sigpending",0)
        elif syscallNum[i]==177:
                idc.set_cmt(addrList[i]+2,"syscall: rt_sigtimedwait",0)
        elif syscallNum[i]==178:
                idc.set_cmt(addrList[i]+2,"syscall: rt_sigqueueinfo",0)
        elif syscallNum[i]==179:
                idc.set_cmt(addrList[i]+2,"syscall: rt_sigsuspend",0)
        elif syscallNum[i]==180:
                idc.set_cmt(addrList[i]+2,"syscall: pread64",0)
        elif syscallNum[i]==181:
                idc.set_cmt(addrList[i]+2,"syscall: pwrite64",0)
        elif syscallNum[i]==182:
                idc.set_cmt(addrList[i]+2,"syscall: chown",0)
        elif syscallNum[i]==183:
                idc.set_cmt(addrList[i]+2,"syscall: getcwd",0)
        elif syscallNum[i]==184:
                idc.set_cmt(addrList[i]+2,"syscall: capget",0)
        elif syscallNum[i]==185:
                idc.set_cmt(addrList[i]+2,"syscall: capset",0)
        elif syscallNum[i]==186:
                idc.set_cmt(addrList[i]+2,"syscall: sigaltstack",0)
        elif syscallNum[i]==187:
                idc.set_cmt(addrList[i]+2,"syscall: sendfile",0)
        elif syscallNum[i]==188:
                idc.set_cmt(addrList[i]+2,"syscall: not implemented",0)
        elif syscallNum[i]==189:
                idc.set_cmt(addrList[i]+2,"syscall: not implemented",0)
        elif syscallNum[i]==190:
                idc.set_cmt(addrList[i]+2,"syscall: vfork",0)
        elif syscallNum[i]==191:
                idc.set_cmt(addrList[i]+2,"syscall: ugetrlimit",0)
        elif syscallNum[i]==192:
                idc.set_cmt(addrList[i]+2,"syscall: mmap2",0)
        elif syscallNum[i]==193:
                idc.set_cmt(addrList[i]+2,"syscall: truncate64",0)
        elif syscallNum[i]==194:
                idc.set_cmt(addrList[i]+2,"syscall: ftruncate64",0)
        elif syscallNum[i]==195:
                idc.set_cmt(addrList[i]+2,"syscall: stat64",0)
        elif syscallNum[i]==196:
                idc.set_cmt(addrList[i]+2,"syscall: lstat64",0)
        elif syscallNum[i]==197:
                idc.set_cmt(addrList[i]+2,"syscall: fstat64",0)
        elif syscallNum[i]==198:
                idc.set_cmt(addrList[i]+2,"syscall: lchown32",0)
        elif syscallNum[i]==199:
                idc.set_cmt(addrList[i]+2,"syscall: getuid32",0)
        elif syscallNum[i]==200:
                idc.set_cmt(addrList[i]+2,"syscall: getgid32",0)
        elif syscallNum[i]==201:
                idc.set_cmt(addrList[i]+2,"syscall: geteuid32",0)
        elif syscallNum[i]==202:
                idc.set_cmt(addrList[i]+2,"syscall: getegid32",0)
        elif syscallNum[i]==203:
                idc.set_cmt(addrList[i]+2,"syscall: setreuid32",0)
        elif syscallNum[i]==204:
                idc.set_cmt(addrList[i]+2,"syscall: setregid32",0)
        elif syscallNum[i]==205:
                idc.set_cmt(addrList[i]+2,"syscall: getgroups32",0)
        elif syscallNum[i]==206:
                idc.set_cmt(addrList[i]+2,"syscall: setgroups32",0)
        elif syscallNum[i]==207:
                idc.set_cmt(addrList[i]+2,"syscall: fchown32",0)
        elif syscallNum[i]==208:
                idc.set_cmt(addrList[i]+2,"syscall: setresuid32",0)
        elif syscallNum[i]==209:
                idc.set_cmt(addrList[i]+2,"syscall: getresuid32",0)
        elif syscallNum[i]==210:
                idc.set_cmt(addrList[i]+2,"syscall: setresgid32",0)
        elif syscallNum[i]==211:
                idc.set_cmt(addrList[i]+2,"syscall: getresgid32",0)
        elif syscallNum[i]==212:
                idc.set_cmt(addrList[i]+2,"syscall: chown32",0)
        elif syscallNum[i]==213:
                idc.set_cmt(addrList[i]+2,"syscall: setuid32",0)
        elif syscallNum[i]==214:
                idc.set_cmt(addrList[i]+2,"syscall: setgid32",0)
        elif syscallNum[i]==215:
                idc.set_cmt(addrList[i]+2,"syscall: setfsuid32",0)
        elif syscallNum[i]==216:
                idc.set_cmt(addrList[i]+2,"syscall: setfsgid32",0)
        elif syscallNum[i]==217:
                idc.set_cmt(addrList[i]+2,"syscall: getdents64",0)
        elif syscallNum[i]==218:
                idc.set_cmt(addrList[i]+2,"syscall: pivot_root",0)
        elif syscallNum[i]==219:
                idc.set_cmt(addrList[i]+2,"syscall: mincore",0)
        elif syscallNum[i]==220:
                idc.set_cmt(addrList[i]+2,"syscall: madvise",0)
        elif syscallNum[i]==221:
                idc.set_cmt(addrList[i]+2,"syscall: fcntl64",0)
        elif syscallNum[i]==222:
                idc.set_cmt(addrList[i]+2,"syscall: not implemented",0)
        elif syscallNum[i]==223:
                idc.set_cmt(addrList[i]+2,"syscall: not implemented",0)
        elif syscallNum[i]==224:
                idc.set_cmt(addrList[i]+2,"syscall: gettid",0)
        elif syscallNum[i]==225:
                idc.set_cmt(addrList[i]+2,"syscall: readahead",0)
        elif syscallNum[i]==226:
                idc.set_cmt(addrList[i]+2,"syscall: setxattr",0)
        elif syscallNum[i]==227:
                idc.set_cmt(addrList[i]+2,"syscall: lsetxattr",0)
        elif syscallNum[i]==228:
                idc.set_cmt(addrList[i]+2,"syscall: fsetxattr",0)
        elif syscallNum[i]==229:
                idc.set_cmt(addrList[i]+2,"syscall: getxattr",0)
        elif syscallNum[i]==230:
                idc.set_cmt(addrList[i]+2,"syscall: lgetxattr",0)
        elif syscallNum[i]==231:
                idc.set_cmt(addrList[i]+2,"syscall: fgetxattr",0)
        elif syscallNum[i]==232:
                idc.set_cmt(addrList[i]+2,"syscall: listxattr",0)
        elif syscallNum[i]==233:
                idc.set_cmt(addrList[i]+2,"syscall: llistxattr",0)
        elif syscallNum[i]==234:
                idc.set_cmt(addrList[i]+2,"syscall: flistxattr",0)
        elif syscallNum[i]==235:
                idc.set_cmt(addrList[i]+2,"syscall: removexattr",0)
        elif syscallNum[i]==236:
                idc.set_cmt(addrList[i]+2,"syscall: lremovexattr",0)
        elif syscallNum[i]==237:
                idc.set_cmt(addrList[i]+2,"syscall: fremovexattr",0)
        elif syscallNum[i]==238:
                idc.set_cmt(addrList[i]+2,"syscall: tkill",0)
        elif syscallNum[i]==239:
                idc.set_cmt(addrList[i]+2,"syscall: sendfile64",0)
        elif syscallNum[i]==240:
                idc.set_cmt(addrList[i]+2,"syscall: futex",0)
        elif syscallNum[i]==241:
                idc.set_cmt(addrList[i]+2,"syscall: sched_setaffinity",0)
        elif syscallNum[i]==242:
                idc.set_cmt(addrList[i]+2,"syscall: sched_getaffinity",0)
        elif syscallNum[i]==243:
                idc.set_cmt(addrList[i]+2,"syscall: io_setup",0)
        elif syscallNum[i]==244:
                idc.set_cmt(addrList[i]+2,"syscall: io_destroy",0)
        elif syscallNum[i]==245:
                idc.set_cmt(addrList[i]+2,"syscall: io_getevents",0)
        elif syscallNum[i]==246:
                idc.set_cmt(addrList[i]+2,"syscall: io_submit",0)
        elif syscallNum[i]==247:
                idc.set_cmt(addrList[i]+2,"syscall: io_cancel",0)
        elif syscallNum[i]==248:
                idc.set_cmt(addrList[i]+2,"syscall: exit_group",0)
        elif syscallNum[i]==249:
                idc.set_cmt(addrList[i]+2,"syscall: lookup_dcookie",0)
        elif syscallNum[i]==250:
                idc.set_cmt(addrList[i]+2,"syscall: epoll_create",0)
        elif syscallNum[i]==251:
                idc.set_cmt(addrList[i]+2,"syscall: epoll_ctl",0)
        elif syscallNum[i]==252:
                idc.set_cmt(addrList[i]+2,"syscall: epoll_wait",0)
        elif syscallNum[i]==253:
                idc.set_cmt(addrList[i]+2,"syscall: remap_file_pages",0)
        elif syscallNum[i]==254:
                idc.set_cmt(addrList[i]+2,"syscall: not implemented",0)
        elif syscallNum[i]==255:
                idc.set_cmt(addrList[i]+2,"syscall: not implemented",0)
        elif syscallNum[i]==256:
                idc.set_cmt(addrList[i]+2,"syscall: set_tid_address",0)
        elif syscallNum[i]==257:
                idc.set_cmt(addrList[i]+2,"syscall: timer_create",0)
        elif syscallNum[i]==258:
                idc.set_cmt(addrList[i]+2,"syscall: timer_settime",0)
        elif syscallNum[i]==259:
                idc.set_cmt(addrList[i]+2,"syscall: timer_gettime",0)
        elif syscallNum[i]==260:
                idc.set_cmt(addrList[i]+2,"syscall: timer_getoverrun",0)
        elif syscallNum[i]==261:
                idc.set_cmt(addrList[i]+2,"syscall: timer_delete",0)
        elif syscallNum[i]==262:
                idc.set_cmt(addrList[i]+2,"syscall: clock_settime",0)
        elif syscallNum[i]==263:
                idc.set_cmt(addrList[i]+2,"syscall: clock_gettime",0)
        elif syscallNum[i]==264:
                idc.set_cmt(addrList[i]+2,"syscall: clock_getres",0)
        elif syscallNum[i]==265:
                idc.set_cmt(addrList[i]+2,"syscall: clock_nanosleep",0)
        elif syscallNum[i]==266:
                idc.set_cmt(addrList[i]+2,"syscall: statfs64",0)
        elif syscallNum[i]==267:
                idc.set_cmt(addrList[i]+2,"syscall: fstatfs64",0)
        elif syscallNum[i]==268:
                idc.set_cmt(addrList[i]+2,"syscall: tgkill",0)
        elif syscallNum[i]==269:
                idc.set_cmt(addrList[i]+2,"syscall: utimes",0)
        elif syscallNum[i]==270:
                idc.set_cmt(addrList[i]+2,"syscall: arm_fadvise64_64",0)
        elif syscallNum[i]==271:
                idc.set_cmt(addrList[i]+2,"syscall: pciconfig_iobase",0)
        elif syscallNum[i]==272:
                idc.set_cmt(addrList[i]+2,"syscall: pciconfig_read",0)
        elif syscallNum[i]==273:
                idc.set_cmt(addrList[i]+2,"syscall: pciconfig_write",0)
        elif syscallNum[i]==274:
                idc.set_cmt(addrList[i]+2,"syscall: mq_open",0)
        elif syscallNum[i]==275:
                idc.set_cmt(addrList[i]+2,"syscall: mq_unlink",0)
        elif syscallNum[i]==276:
                idc.set_cmt(addrList[i]+2,"syscall: mq_timedsend",0)
        elif syscallNum[i]==277:
                idc.set_cmt(addrList[i]+2,"syscall: mq_timedreceive",0)
        elif syscallNum[i]==278:
                idc.set_cmt(addrList[i]+2,"syscall: mq_notify",0)
        elif syscallNum[i]==279:
                idc.set_cmt(addrList[i]+2,"syscall: mq_getsetattr",0)
        elif syscallNum[i]==280:
                idc.set_cmt(addrList[i]+2,"syscall: waitid",0)
        elif syscallNum[i]==281:
                idc.set_cmt(addrList[i]+2,"syscall: socket",0)
        elif syscallNum[i]==282:
                idc.set_cmt(addrList[i]+2,"syscall: bind",0)
        elif syscallNum[i]==283:
                idc.set_cmt(addrList[i]+2,"syscall: connect",0)
        elif syscallNum[i]==284:
                idc.set_cmt(addrList[i]+2,"syscall: listen",0)
        elif syscallNum[i]==285:
                idc.set_cmt(addrList[i]+2,"syscall: accept",0)
        elif syscallNum[i]==286:
                idc.set_cmt(addrList[i]+2,"syscall: getsockname",0)
        elif syscallNum[i]==287:
                idc.set_cmt(addrList[i]+2,"syscall: getpeername",0)
        elif syscallNum[i]==288:
                idc.set_cmt(addrList[i]+2,"syscall: socketpair",0)
        elif syscallNum[i]==289:
                idc.set_cmt(addrList[i]+2,"syscall: send",0)
        elif syscallNum[i]==290:
                idc.set_cmt(addrList[i]+2,"syscall: sendto",0)
        elif syscallNum[i]==291:
                idc.set_cmt(addrList[i]+2,"syscall: recv",0)
        elif syscallNum[i]==292:
                idc.set_cmt(addrList[i]+2,"syscall: recvfrom",0)
        elif syscallNum[i]==293:
                idc.set_cmt(addrList[i]+2,"syscall: shutdown",0)
        elif syscallNum[i]==294:
                idc.set_cmt(addrList[i]+2,"syscall: setsockopt",0)
        elif syscallNum[i]==295:
                idc.set_cmt(addrList[i]+2,"syscall: getsockopt",0)
        elif syscallNum[i]==296:
                idc.set_cmt(addrList[i]+2,"syscall: sendmsg",0)
        elif syscallNum[i]==297:
                idc.set_cmt(addrList[i]+2,"syscall: recvmsg",0)
        elif syscallNum[i]==298:
                idc.set_cmt(addrList[i]+2,"syscall: semop",0)
        elif syscallNum[i]==299:
                idc.set_cmt(addrList[i]+2,"syscall: semget",0)
        elif syscallNum[i]==300:
                idc.set_cmt(addrList[i]+2,"syscall: semctl",0)
        elif syscallNum[i]==301:
                idc.set_cmt(addrList[i]+2,"syscall: msgsnd",0)
        elif syscallNum[i]==302:
                idc.set_cmt(addrList[i]+2,"syscall: msgrcv",0)
        elif syscallNum[i]==303:
                idc.set_cmt(addrList[i]+2,"syscall: msgget",0)
        elif syscallNum[i]==304:
                idc.set_cmt(addrList[i]+2,"syscall: msgctl",0)
        elif syscallNum[i]==305:
                idc.set_cmt(addrList[i]+2,"syscall: shmat",0)
        elif syscallNum[i]==306:
                idc.set_cmt(addrList[i]+2,"syscall: shmdt",0)
        elif syscallNum[i]==307:
                idc.set_cmt(addrList[i]+2,"syscall: shmget",0)
        elif syscallNum[i]==308:
                idc.set_cmt(addrList[i]+2,"syscall: shmctl",0)
        elif syscallNum[i]==309:
                idc.set_cmt(addrList[i]+2,"syscall: add_key",0)
        elif syscallNum[i]==310:
                idc.set_cmt(addrList[i]+2,"syscall: request_key",0)
        elif syscallNum[i]==311:
                idc.set_cmt(addrList[i]+2,"syscall: keyctl",0)
        elif syscallNum[i]==312:
                idc.set_cmt(addrList[i]+2,"syscall: semtimedop",0)
        elif syscallNum[i]==313:
                idc.set_cmt(addrList[i]+2,"syscall: vserver",0)
        elif syscallNum[i]==314:
                idc.set_cmt(addrList[i]+2,"syscall: ioprio_set",0)
        elif syscallNum[i]==315:
                idc.set_cmt(addrList[i]+2,"syscall: ioprio_get",0)
        elif syscallNum[i]==316:
                idc.set_cmt(addrList[i]+2,"syscall: inotify_init",0)
        elif syscallNum[i]==317:
                idc.set_cmt(addrList[i]+2,"syscall: inotify_add_watch",0)
        elif syscallNum[i]==318:
                idc.set_cmt(addrList[i]+2,"syscall: inotify_rm_watch",0)
        elif syscallNum[i]==319:
                idc.set_cmt(addrList[i]+2,"syscall: mbind",0)
        elif syscallNum[i]==320:
                idc.set_cmt(addrList[i]+2,"syscall: get_mempolicy",0)
        elif syscallNum[i]==321:
                idc.set_cmt(addrList[i]+2,"syscall: set_mempolicy",0)
        elif syscallNum[i]==322:
                idc.set_cmt(addrList[i]+2,"syscall: openat",0)
        elif syscallNum[i]==323:
                idc.set_cmt(addrList[i]+2,"syscall: mkdirat",0)
        elif syscallNum[i]==324:
                idc.set_cmt(addrList[i]+2,"syscall: mknodat",0)
        elif syscallNum[i]==325:
                idc.set_cmt(addrList[i]+2,"syscall: fchownat",0)
        elif syscallNum[i]==326:
                idc.set_cmt(addrList[i]+2,"syscall: futimesat",0)
        elif syscallNum[i]==327:
                idc.set_cmt(addrList[i]+2,"syscall: fstatat64",0)
        elif syscallNum[i]==328:
                idc.set_cmt(addrList[i]+2,"syscall: unlinkat",0)
        elif syscallNum[i]==329:
                idc.set_cmt(addrList[i]+2,"syscall: renameat",0)
        elif syscallNum[i]==330:
                idc.set_cmt(addrList[i]+2,"syscall: linkat",0)
        elif syscallNum[i]==331:
                idc.set_cmt(addrList[i]+2,"syscall: symlinkat",0)
        elif syscallNum[i]==332:
                idc.set_cmt(addrList[i]+2,"syscall: readlinkat",0)
        elif syscallNum[i]==333:
                idc.set_cmt(addrList[i]+2,"syscall: fchmodat",0)
        elif syscallNum[i]==334:
                idc.set_cmt(addrList[i]+2,"syscall: faccessat",0)
        elif syscallNum[i]==335:
                idc.set_cmt(addrList[i]+2,"syscall: pselect6",0)
        elif syscallNum[i]==336:
                idc.set_cmt(addrList[i]+2,"syscall: ppoll",0)
        elif syscallNum[i]==337:
                idc.set_cmt(addrList[i]+2,"syscall: unshare",0)
        elif syscallNum[i]==338:
                idc.set_cmt(addrList[i]+2,"syscall: set_robust_list",0)
        elif syscallNum[i]==339:
                idc.set_cmt(addrList[i]+2,"syscall: get_robust_list",0)
        elif syscallNum[i]==340:
                idc.set_cmt(addrList[i]+2,"syscall: splice",0)
        elif syscallNum[i]==341:
                idc.set_cmt(addrList[i]+2,"syscall: arm_sync_file_range",0)
        elif syscallNum[i]==341:
                idc.set_cmt(addrList[i]+2,"syscall: sync_file_range2",0)
        elif syscallNum[i]==342:
                idc.set_cmt(addrList[i]+2,"syscall: tee",0)
        elif syscallNum[i]==343:
                idc.set_cmt(addrList[i]+2,"syscall: vmsplice",0)
        elif syscallNum[i]==344:
                idc.set_cmt(addrList[i]+2,"syscall: move_pages",0)
        elif syscallNum[i]==345:
                idc.set_cmt(addrList[i]+2,"syscall: getcpu",0)
        elif syscallNum[i]==346:
                idc.set_cmt(addrList[i]+2,"syscall: epoll_pwait",0)
        elif syscallNum[i]==347:
                idc.set_cmt(addrList[i]+2,"syscall: kexec_load",0)
        elif syscallNum[i]==348:
                idc.set_cmt(addrList[i]+2,"syscall: utimensat",0)
        elif syscallNum[i]==349:
                idc.set_cmt(addrList[i]+2,"syscall: signalfd",0)
        elif syscallNum[i]==350:
                idc.set_cmt(addrList[i]+2,"syscall: timerfd_create",0)
        elif syscallNum[i]==351:
                idc.set_cmt(addrList[i]+2,"syscall: eventfd",0)
        elif syscallNum[i]==352:
                idc.set_cmt(addrList[i]+2,"syscall: fallocate",0)
        elif syscallNum[i]==353:
                idc.set_cmt(addrList[i]+2,"syscall: timerfd_settime",0)
        elif syscallNum[i]==354:
                idc.set_cmt(addrList[i]+2,"syscall: timerfd_gettime",0)
        elif syscallNum[i]==355:
                idc.set_cmt(addrList[i]+2,"syscall: signalfd4",0)
        elif syscallNum[i]==356:
                idc.set_cmt(addrList[i]+2,"syscall: eventfd2",0)
        elif syscallNum[i]==357:
                idc.set_cmt(addrList[i]+2,"syscall: epoll_create1",0)
        elif syscallNum[i]==358:
                idc.set_cmt(addrList[i]+2,"syscall: dup3",0)
        elif syscallNum[i]==359:
                idc.set_cmt(addrList[i]+2,"syscall: pipe2",0)
        elif syscallNum[i]==360:
                idc.set_cmt(addrList[i]+2,"syscall: inotify_init1",0)
        elif syscallNum[i]==361:
                idc.set_cmt(addrList[i]+2,"syscall: preadv",0)
        elif syscallNum[i]==362:
                idc.set_cmt(addrList[i]+2,"syscall: pwritev",0)
        elif syscallNum[i]==363:
                idc.set_cmt(addrList[i]+2,"syscall: rt_tgsigqueueinfo",0)
        elif syscallNum[i]==364:
                idc.set_cmt(addrList[i]+2,"syscall: perf_event_open",0)
        elif syscallNum[i]==365:
                idc.set_cmt(addrList[i]+2,"syscall: recvmmsg",0)
        elif syscallNum[i]==366:
                idc.set_cmt(addrList[i]+2,"syscall: accept4",0)
        elif syscallNum[i]==367:
                idc.set_cmt(addrList[i]+2,"syscall: fanotify_init",0)
        elif syscallNum[i]==368:
                idc.set_cmt(addrList[i]+2,"syscall: fanotify_mark",0)
        elif syscallNum[i]==369:
                idc.set_cmt(addrList[i]+2,"syscall: prlimit64",0)
        elif syscallNum[i]==370:
                idc.set_cmt(addrList[i]+2,"syscall: name_to_handle_at",0)
        elif syscallNum[i]==371:
                idc.set_cmt(addrList[i]+2,"syscall: open_by_handle_at",0)
        elif syscallNum[i]==372:
                idc.set_cmt(addrList[i]+2,"syscall: clock_adjtime",0)
        elif syscallNum[i]==373:
                idc.set_cmt(addrList[i]+2,"syscall: syncfs",0)
        elif syscallNum[i]==374:
                idc.set_cmt(addrList[i]+2,"syscall: sendmmsg",0)
        elif syscallNum[i]==375:
                idc.set_cmt(addrList[i]+2,"syscall: setns",0)
        elif syscallNum[i]==376:
                idc.set_cmt(addrList[i]+2,"syscall: process_vm_readv",0)
        elif syscallNum[i]==377:
                idc.set_cmt(addrList[i]+2,"syscall: process_vm_writev",0)
        elif syscallNum[i]==378:
                idc.set_cmt(addrList[i]+2,"syscall: kcmp",0)
        elif syscallNum[i]==379:
                idc.set_cmt(addrList[i]+2,"syscall: finit_module",0)
        elif syscallNum[i]==380:
                idc.set_cmt(addrList[i]+2,"syscall: sched_setattr",0)
        elif syscallNum[i]==381:
                idc.set_cmt(addrList[i]+2,"syscall: sched_getattr",0)
        elif syscallNum[i]==382:
                idc.set_cmt(addrList[i]+2,"syscall: renameat2",0)
        elif syscallNum[i]==383:
                idc.set_cmt(addrList[i]+2,"syscall: seccomp",0)
        elif syscallNum[i]==384:
                idc.set_cmt(addrList[i]+2,"syscall: getrandom",0)
        elif syscallNum[i]==385:
                idc.set_cmt(addrList[i]+2,"syscall: memfd_create",0)
        elif syscallNum[i]==386:
                idc.set_cmt(addrList[i]+2,"syscall: bpf",0)
        elif syscallNum[i]==387:
                idc.set_cmt(addrList[i]+2,"syscall: execveat",0)
        elif syscallNum[i]==388:
                idc.set_cmt(addrList[i]+2,"syscall: userfaultfd",0)
        elif syscallNum[i]==389:
                idc.set_cmt(addrList[i]+2,"syscall: membarrier",0)
        elif syscallNum[i]==390:
                idc.set_cmt(addrList[i]+2,"syscall: mlock2",0)
        elif syscallNum[i]==391:
                idc.set_cmt(addrList[i]+2,"syscall: copy_file_range",0)
        elif syscallNum[i]==392:
                idc.set_cmt(addrList[i]+2,"syscall: preadv2",0)
        elif syscallNum[i]==393:
                idc.set_cmt(addrList[i]+2,"syscall: pwritev2",0)
        elif syscallNum[i]==394:
                idc.set_cmt(addrList[i]+2,"syscall: pkey_mprotect",0)
        elif syscallNum[i]==395:
                idc.set_cmt(addrList[i]+2,"syscall: pkey_alloc",0)
        elif syscallNum[i]==396:
                idc.set_cmt(addrList[i]+2,"syscall: pkey_free",0)
        elif syscallNum[i]==397:
                idc.set_cmt(addrList[i]+2,"syscall: statx",0)
        elif syscallNum[i]==983041:
                idc.set_cmt(addrList[i]+2,"syscall: ARM_breakpoint",0)
        elif syscallNum[i]==983042:
                idc.set_cmt(addrList[i]+2,"syscall: ARM_cacheflush",0)
        elif syscallNum[i]==983043:
                idc.set_cmt(addrList[i]+2,"syscall: ARM_usr26",0)
        elif syscallNum[i]==983044:
                idc.set_cmt(addrList[i]+2,"syscall: ARM_usr32",0)
        elif syscallNum[i]==983045:
                idc.set_cmt(addrList[i]+2,"syscall: ARM_set_tls",0)
        else:
                idc.set_cmt(addrList[i]+2,"error",0)
        i=i+1
    
def findMovSvc(startAddr,endAddr,addrList): 
    while startAddr < endAddr:
        addr=idc.find_binary(startAddr, 1, "A0 E3 00 00 00 EF")
        if startAddr==idc.BADADDR:
            break
        else:
            addrList.append(addr)
            startAddr=addr+1

    del addrList[-1]

def findLDRSvc(startAddr,endAddr,addrList):
    while startAddr < endAddr:
        addr=idc.find_binary(startAddr, 1, "9F E5 00 00 00 EF")
        if startAddr==idc.BADADDR:
            break
        else:
            addrList.append(addr)
            startAddr=addr+1

    del addrList[-1]

def findMOVWSvc(startAddr,endAddr,addrList):
    while startAddr < endAddr:
        addr=idc.find_binary(startAddr, 1, "00 E3 00 00 00 EF")
        if startAddr==idc.BADADDR:
            break
        else:
            addrList.append(addr)
            startAddr=addr+1

    del addrList[-1]


def main():
    startAddr=ida_ida.inf_get_min_ea() #시작주소
    endAddr=ida_ida.inf_get_max_ea() #끝주소
    totalList=[] #instruction이 'SVC 0'인 주소
    
    ############################################# 
        
    addrList=[] # "MOV a b" "SVC 0" 찾기 위한 리스트
    syscallNum=[] # syscall Number 저장을 위한 리스트
    
    findMovSvc(startAddr,endAddr,addrList) #처음부터 끝까지 "MOV a b" "SVC 0" 찾아서 addrList[]에 저장
    totalList.append(addrList) 
    
    for i in addrList:
        syscallNum.append(get_wide_byte(i-2)) #syscall Numer 찾기
    
    writeCmt(addrList,syscallNum) #해당하는 syscall 찾은 후 해당 주소에 comment 달기
    
    #############################################
    
    addrList2=[] # "LDR a b" "SVC 0" 찾기 위한 리스트
    
    findLDRSvc(startAddr,endAddr,addrList2) # 처음부터 끝까지 "LDR a b" "SVC 0" 찾아서 addrList2[]에 저장
    totalList.append(addrList2)
    
    #syscall Number 찾기
    opnd=[]
    rgx=re.compile('=\d+')
    i=0
    while i < len(addrList2):
        idc.op_dec(addrList2[i]-2,1) #operand에서 hex로 되어있는 syscall 값을 decimal로 변환
        opnd.append(idc.generate_disasm_line(addrList2[i]-2,0)) #disassembly 내용을 opnd 리스트에 저장
        tmp=rgx.findall(opnd[i])
        opnd[i]=tmp[0]
        opnd[i]=opnd[i].replace('=','') #syscall 값만 추출
        opnd[i]=int(opnd[i]) #type을 str에서 int로 변환
        i=i+1
    
    writeCmt(addrList2,opnd) # 해당하는 syscall 찾은 후 해당 주소에 comment 달기
    
    ############################################
    
    addrList3=[] # "MOVW a b" "SVC 0" 찾기 위한 리스트
    
    findMOVWSvc(startAddr,endAddr,addrList3) # 처음부터 끝까지 "MOVW a b" "SVC 0" 찾아서 addrList3[]에 저장
    totalList.append(addrList3)
    
    #syscall Number 찾기
    opnd2=[]
    rgx2=re.compile('#\d+')
    i=0
    while i < len(addrList3):
        idc.op_dec(addrList3[i]-2,1) #operand에서 hex로 되어있는 syscall 값을 decimal로 변환
        opnd2.append(idc.generate_disasm_line(addrList3[i]-2,0)) #disassembly 내용을 opnd 리스트에 저장
        tmp=rgx2.findall(opnd2[i])
        opnd2[i]=tmp[0]
        opnd2[i]=opnd2[i].replace('#','') #syscall 값만 추출
        opnd2[i]=int(opnd2[i]) #type을 str에서 int로 변환
        i=i+1
    
    writeCmt(addrList3,opnd2) # 해당하는 syscall 찾은 후 해당 주소에 comment 달기
    
    ############################################

    totalList=sum(totalList,[]) # 2차원 리스트 -> 1차원 리스트로 변환
    
    for i in totalList:
        if idc.get_func_name(i+2)=='': #함수 이름이 없는 경우 제외
            continue
        else: # 함수 이름이 있는 경우 출력
            print("Func Name: ",idc.get_func_name(i+2),"   | Address: ",hex(i),"  |",idc.get_cmt(i+2,0),)
            # Func Name : syscall을 호출하는 함수 이름
            # Address : syscall하는 실제 주소
            # syscall : 무슨 syscall인지
                    
if __name__ == '__main__':
         main()
