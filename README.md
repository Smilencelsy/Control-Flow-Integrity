
### Control-Flow Integrity                 
---                
#### 0x00. 从跳转指令开始谈起               
在汇编语言中,根据寻址方式的不同可以分为两种跳转指令。一种是间接跳转指令,另一种是直接跳转指令。        
直接跳转指令的示例如下所示:   

> CALL 0x1060000F      

在程序执行到这条语句时,就会将指令寄存器的值替换为0x1060000F。这种在指令中直接给出跳转地址的寻址方式就叫做直接转移。在高级语言中, 像if-else,静态函数调用这种跳转目标往往可以确定的语句就会被转换为直接跳转指令。                  
                     
间接跳转指令则是使用数据寻址方式间接的指出转移地址，比如:               
> JMP EBX            

执行完这条指令之后, 指令寄存器的值就被替换为EBX寄存器的值。它的转换对象为作为回调参数的函数指针等动态决定目标地址的语句。       
                  
以上是通过寻址方式进行的分类, 在CFI中还有一个比较特殊的分类方式, 就是前向和后向转移。        
这个比较容易理解, 将控制权定向到程序中一个新位置的转移方式, 就叫做前向转移, 比如jmp和call指令             
而将控制权返回到先前位置的就叫做后向转移, 最常见的就是ret指令。        
                  
将以上两种分类方式结合起来, 前向转移指令call和jmp根据寻址方式不同, 又可以分为直接jmp, 间接jmp，直接call，间接call四种。而后向转移指令ret没有操作数，它的目标地址计算是通过从栈中弹出的数来决定的。正因为ret指令的特性，引发了一系列针对返回地址的攻击。


#### 0x01. CFI发展历史和提出原因                   
* 早期防护      
在软件安全防护还不够发达的年代，一般攻击程序的思路是通过栈溢出覆盖程序中的某个返回地址，然后在该地址上布置shellcode,将控制流劫持到shellcode。为了阻止此类攻击，在硬件的支持下实现了DEP（Data-Execution-Prevention NX/w异或x）机制，限制内存页不能同时写和执行，阻止了攻击者写入恶意代码。但DEP只限制了恶意代码的写入，攻击者们又想到了代码重用攻击，即利用程序或相关库中已有的代码拼接成恶意代码。代码重用攻击包括Ret2Libc(通过整个函数)、ROP(通过多个ret指令)、JOP(通过间接调用call)等。当程序的代码量足够大时，是可以找到足够多的gadget进行代码重用攻击的。         
        
* CFI的提出        
为了抵御控制流劫持的攻击，2005年CCS上发表了一篇名为《Control-Flow Integrity》的文章，正式提出了CFI的概念。     
CFI防御机制的核心思想是限制程序运行中的控制流转移，使其始终处于原有的控制流图所限定的范围内。具体做法是分析程序的控制流图(CFG),获取间接转移指令目标的白名单，运行时核对间接转移指令的目标是否在白名单中。控制流劫持往往会违背原有的控制流图，CFI则使这种行为难以实现。               
从实现角度上看，又粗粒度和细粒度两种CFI。细粒度CFI严格控制每一个见解转移指令的目标，这会引入很大的开销。粗粒度CFI则是将一组类似或相近类型的目标整理到一起检查，但这种方法会导致安全性下降。                 

* CFI的改进       
严格意义上的CFI需要对每条间接转移指令都进行检查，但插桩引起的开销过大，需要额外信息的支持(比如间接跳转可能的目标集合)，且不能进行增量式的部署。因此又提出了对间接调用指令和函数返回指令的目标进行区分，阻止未经验证的返回指令跳转到敏感函数的行为的CCFIR。它是一个纯粹的二进制转换程序，不依赖源码和调试信息，只依赖重定位表中的信息。CFI、CCFIR、binCFI 都属于粗粒度的 CFI 机制，粗粒度的 CFI 可以降低开销，但是会带来安全上的问题。          

* 针对粗粒度CFI的攻击      
2014 年的论文《Out of Control: Overcoming Control-Flow Integrity》,DOI: 10.1109/SP.2014.43，中提到了一种攻击手段。他们利用了两种特殊的 Gadget：entry point(EP) gadget 和 call site(CS) gadget，来绕开粗粒度 CFI 机制的防御。2015 年的论文《Losing Control: On the Effectiveness of Control-Flow Integrity under Stack Attacks》,DOI: 10.1145/2810103.2813671，也提到了对 CFI 保护下的栈的攻击手段。在此论文发表前，通过影子栈（Shadow Stack）来检测函数返回目标，再加上 DEP 和 ASLR 的保护，栈应该会变得非常安全，但是事实并非如此。这篇论文中提到了三种攻击手段，他们提出了三种攻击方法：一是利用堆上的漏洞来破坏栈上的 calleesaved 寄 存 器 保 存 区 域， 使得calleesaved 寄存器被劫持；二是利用用户空间和内核之间进行上下文切换的问题，来劫持 sysenter 指令，使控制跳转到攻击者想跳转的位置；三是通过泄露主栈的地址来泄露出 shadow stack 的地址，进而进行攻击。        

* 上下文敏感CFI的提出      
以往 CFI 方案的问题是只实施了控制流不敏感策略，粗粒度 CFI 则是将一组类似或相近类型的目标归到一起进行检查，这种检查还是有一些问题的。因此，上下文敏感的 CFI（Context sensitive CFI）应运而生。它依赖于上下文敏感的静态分析，将 CFI 不变量和 CFG 中的控制流路径联系到一起，运行时在执行路径上强制执行这些不变量。2015 年论文：《CCFI: Cryptographically Enforced Control Flow Integrity》, 提出了一种通过对代码指针加密的方法来增强 CFI 的保护。（这应该是理论上可行现实中做不到的脑洞，因为开销实在是太大）这个观点出发点是好的，但是在大部分硬件效率跟不上的情况下，几乎不可能在现实中运用，因此 CCFI 被废弃。2014 年的论文：《Complete Control-Flow Integrity for Commodity Operating System Kernels》，他们在操作系统的内核上实现了 CFI，使之免受控制流劫持等攻击，这个系统被称为 KCoFI。他们在基于标签的控制流间接转移保护的基础上，加入一个运行时监控的软件层，负责保护一些关键的操作系统数据结构和监控操作系统进行的所有底层状态操作。（这个系统加入了实时监控系统底层状态操作，如果是高 IO 的情况下，性能表现比较差)       

#### 0x02. CFI的原理        


#### 0x03. CFI的分类         


#### 0x04. 不同CFI的比较(性能、安全性)         
定性安全保证 => 定量安全计算      
性能开销 => 部分用文献中的结果, 最新版本自行测试      
以上测试基于SPEC CPU2006基准测试程序

#### 0x05. CFI的应用范围、发展前景         
* Clang: https://en.wikipedia.org/wiki/Clang (一个编译器前端，用LLVM编译器架构作为其后端)         
* Microsoft's Control Flow Guard：https://en.wikipedia.org/wiki/Control-flow_integrity       
* Return Flow Guard: https://xlab.tencent.com/en/2016/11/02/return-flow-guard/ (腾讯玄武实验室)      
* Google's Indirect Function-Call Checks (第六篇论文 Enforcing)      
* Reuse Attack Protector： https://grsecurity.net/rap_faq.php (RAP)

#### 0x06. 个人想法              
+ 粗粒度的CFI安全性不够       
+ 细粒度的CFI性能开销太大      
+ 出现很多CFI无法防护的攻击——Data oriented programming(上一节课讲过的DOP)

### 参考文献
---
+ 吴世忠郭涛董国伟张普含， 软件漏洞分析技术 ，科学出版社，2014. 
+ Bryant &O’Hallaron, Computer Systems: A Programmer’s Perspective (2 ed.) , Pearson Education, 2011.中译本: 深入理解计算机系统，机械工业出版社, 2011. 
+ David Brumley and Vyas Sekar, Introduction to Computer Security (18487/15487), 2015
