"""Bounded byte construction only. No imports from a resolver or classification oracle."""
import argparse
import atexit
import base64
import hashlib
import io
import json
from pathlib import Path
import re
import runpy
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zlib

HERE = Path(__file__).resolve().parent
STORE = HERE / "corpus"
ACCEPTED = "9bba9b9c0afff93dd003f6b14d34b82292a2f8a7"
LP01_APPROVED_BEFORE = {
    "decision": "escalated",
    "evidence_contract": (
        "Checked package SPDX expression: all alternatives OSI-approved by SPDX 3.27.0 "
        "and non-copyleft under pinned policy 1.0.0; owner grant and release/source scope not established."),
    "finding": None,
    "missing_fact": (
        "An OSI-approved, non-copyleft package declaration does not establish an owner-authorized "
        "repository license grant or correspondence to the checked release/source scope."),
    "required_input": "owner-license-grant-and-release-scope",
    "next_category": "package-owner",
}
LP01_APPROVED_VERIFIED = {
    "decision": "deterministic",
    "evidence_contract": (
        "Checked package SPDX expression: every offered alternative is OSI-approved by SPDX 3.27.0 "
        "and non-copyleft under pinned policy 1.0.0; classification is limited to this exact package declaration."),
    "finding": (
        "The checked package SPDX license expression is OSI-approved and non-copyleft under "
        "the pinned policy for every offered alternative. This classifies the exact package "
        "declaration; it does not legally interpret other repository files or other releases."),
    "missing_fact": None,
    "required_input": None,
    "next_category": None,
}
LP03_LEGACY_PINS = {
    "lp03/cases.json": "935bc6e80fcaf7d1a5ad1526b2ee5a2409d6041fdbccfd6fb1b47e272b1f744b",
    "lp03/acceptance.json": "5f6a5a58c73939e7cb3f28f740acfcf26e2cfd883f0ebfb0f99d63ad1e50e255",
}


PARENT_PATCHES_B85 = (
    "c-ri}+j1mFlBW48ki40j1Zn3(_EpJD@9v1~%=S*VNRMnwONkwm(S;0P5CK-@wDi00r-2BZ0kW#dB$;JZ$xIwP+}zYu_5ak&-2LC*"
    "wXz$#cOU-!-NlvC-<H<K)xK=o_~zesm)mzA{^ei({XgFS`@25cX19?ayc@e#F3NuNckkbg?>BvL@bBB@c7I*kp5OoH??(H>=x0}@"
    "{h@puXaD#Q|K)$4jXzyokDZ+1!&$kw;J^L2-j@C5`>{LwfBx~mo|mhu>&x%?Sp9ta3HyzS->9>)?PuG|?RmSr`g}3w{_JMk$MxCO"
    "X1kR(E-yCi^O^oeeWU*F?DCIWe)aLXZ1;!HU5|@F@4nq#-dwkFw&NUwlkLyOZeQxfX7}Cb-_VP>+4jx$<GT;rn~RJ0?>=p~(Cx?H"
    "&)fd|Zu{s0-#@;bQ!g>lMY*O!m)o;`Nv9sQ!{yvw-Fdm$e|LGk`QJk>@9J{5*<W6NKBE_7yBo)Azq~$cm)F?q>T-K9@7ezHZ2#Rj"
    "Ye&<*)G_JEcKm7o`^MOO<fL5s@#4-8P4oNf@xN|1*Q5V_v%R{JzTIBavGwyq>*rYR{Mf+x;mn5*?k+FBAJ@O<zoQ!*Z2s;)-v7(L"
    "{_FeYBg;pAz(@Y|{cVCdq??snmfx)0vV3Iu$nufpBg;pYk1QWqKC*md`N;B-<s-{SmX9nSSw6CSWckSQk>w-HN0yKLntWs(v<_Ma"
    "t%H8k2Q8snLbrTm`N(e!hL%e%mt5+;Vrj+FuPBz5BP~Z-sdPoaih$*9%iC7%zI<e9@<M<Wa4X=Jk1QWqNqHT#4q6ATgBGAI@m=D("
    "4q6ATgVsUopmoqXXdSc;S_l222i-oJ%DnpQyPvR$7oL8#hG!l0BM-VOa^L+EmE`yn#qE>gm7?`QN&4M>f3^GY?YAE{`|ob*H|_G%"
    "w|wZ+)y4SsVpFdRhe(ah&p&PUXWCfjLrhtf+WMHUegDnb@AhZ=&8Kl@lnLirom=%!+I&!oKmXr*s@$^YD!xBVHk|#j$R+KsH$!Fy"
    "{>YVF-cZ_KT~V>#mfDSKc5L^Xa<O}Vtoiq4BU1x&b3uo8H&<7e*L>!zUdqftKl{YTvBRmPKAPY^?aofUx-F`|Is2#YHoFHi1-rAW"
    "8@_7C-=CH5%jTlg&BbPqCH4<bc7C*Hzw602Xa9Bo(zL*#yN6HS9Oom>>SkN$@b2u7<9eLco6W`kY+he}dTg4*3F-9ZOK1HwK2<#7"
    "yUo?vW_vjOg9|zhFg>Qf+a^7`ygu8Pk65sdR&I8KQSIa6vWT@X$hiJ~oXyMYKb&vJ{*U~78uiQiZ=>yZ-~8Aag5`tD2Y+cFTnByS"
    "2R)g-{l{^Ef5=?%^`&^qAwoBjLp~9-w-J0Br~UF-WQ@CzJx1pFG4hTP{G+_?-R-n+xfuNFziqagPdA^=zSn2hHy7i>*&nYj$poj1"
    "+Z-|p(fsLVw?F&585jK+?1wqo?*%Z=Z?=ynu%*+-d~}-%Xy#`7hwbGbw_M(Bfc<{c`RUtd;^0@N`QM%(|Jg14bXxn^jne+t4Oc7Y"
    "e`#*}ATQ^qbSSghWqY~({OR&$cWmRlm8<>D_4w-t@o15!y<UU(D;mVxGRnSMslBw8_4fxvxxS>o_4A(2i&e&-WSEeieYyTP_UH4u"
    "d>RKyy4i}EF1Ht-VT?mFnB+kZ5i1e0gEeot;NtVy@v6a?i_0AyIka)2qRn=9#b|K+-<>g(7vuW;3jHk?n=Zq8(BkpOyK|w5jM)CP"
    "ko3r*gf>QL-<?T@xfVUX8i(bj&u2$_eRKAIm0QY?l`f$GahTov!+66zi1Nb@{HL@1_09e}QSRHz7}saV<*hvi`0tlz7vp2OIJ;dr"
    ";|mVtyw|e+cRdQ{9=jcvylodZhvwfs^U8ZnJdA-@=9$sUj<R?sUV2>N1DTGe`O#3Y#{O?`>`w{dg?W|b55IbUxU<TiAMFp-^fc1v"
    "$CJFWsbLNNFFW|Zd$9N6XeD}fb!hXUU9U$Qo2&g3uXxHH_dWh0{&;ZYaa5L*Ehqa`I@$4~lmn-$UvBp6bhC%HyFQdpM_oG^?RE@~"
    "mOqS6$80B4;&z+uoly>(#kLcZ?Eh*<Je~CXbS39UZ}>9`<(CTC)AtwSNiBPKX`8V-zunAtzGEPEbMv&6?OfOOCkpS~e$$p`|2jPT"
    "enS7BH~a676TMHMUA%1U_M^Wt0PoKRt$aS~GO}Af`MjrR-<926ZoVJcmn?kmYDc4<{6r>?&&p}z=o>paB~<zJaZ}{q$=1#B>52h4"
    "UBH7l{JylC%bOiTdFQp_O7|Xg8sUTOZml7vzc>6@5f?f+-`&L?=2H%H@VCQ>osU-8U&vJd{$SDP$>nx#=Sc>*{o&JSKmByY^NQyc"
    "&nuo^isxI-z!d!I`~gQCjkzNFHx$vo+n>p%{ypYA#q<l2d5rl}Y`iiehxq*qqV;s2!$ZG1tf}8FK>uJY-%84HU7SDVcG|C>{ons^"
    "uI$;za&>Fla<tSXr+g8@f1bE{7&@n$D(-6kRhRwR>#}?2z1zWY=-TZ_9Jg`s!&^l;CBZwhNalZBn3Yd;^HBulrLyegAe-&?B>&CF"
    "@>*4PA5`a0o$B36_{*tR!vDn*{)(#=S1Ya-NG*{18v&{1n9DJjV=l*Bj`@?9p104UxbxZ5wJeYQmG6~!+?C^e`0YOSxj76B*1x~E"
    "<aU@j+0Dtv&tTx~Xf#=_KfmR!Kkyin+jHJN#bl+;l{S~2FUMStxg2vj=5oyCn9DJjV=l*Bj=3CjIp%N4F&`|J9^7o*L-XtQ%I$GU"
    "RQzPS=gjo^!G)LW_TA?D!)D8y?eX~~7vrzHZQ=GN@u!aRmpI$efaj+>DwdP|DxK_qVEOmA_h!9+aKZ2IpPzi3hCE%XY(_30ugCc2"
    "<=bAiyUlKo0nU$;n&+nvE+<+}w47);(Qng<)-9pyme60xEuqUTms>8kTyDACa=GPl%ipM5F0cD_J{Ie=73=OM0bJ?wX20XRM^9(G"
    "+1^d@-aW*IhUK}AFP0;BbI5=84DRxj<tfWkmZvOFS)TIcJ!MU#u8Gv2bRu=_j##@R*0!DHn9DJj>@L||i{Q(NmJ=-}T28c_XgSex"
    "qUA)(iIx*BCt6PQH|0df=es|+jbpjduXd5<_(;IpF*_LNAOGRM{7<a0FBg{|53@?Amsrw(Ofa2%<)vAr<Iw-Wwv*d7PwxScmp8V{"
    ">#LjHk9;$m`>}6k`+sj3NqJWL?S7lX?LT7eO_R3>i>*H1J~#2<0~zn0XMg92|MY+Sw{NlPx%}pwj>~(P<)MgpVgIz*i=*6m#=|?B"
    "IETE4Zhv;%O~X(>@~%IAcX=_+cQ=O@6*Kl1$62_O+r2+t#&_jrx0idPj(%|Wp6J_2Kip)ufA%1GaTRgJc4(@8mM2OcU#EOM=C~GH"
    "?H;;O{~oivKR)O2_%6&_*M5I^({um!`0h@|ioRT39=gdV4iDLp7dpQ``~K#Fua6)5_Vj-1dmnr+&Eu|@^ZxD9huD%adS(DwFFah_"
    "A@pdp9enO?r0@HI7rZ+-*N4&%-g>$HkVh<9)f(b-LABY6%0)HpiZ@gHI*S=YXXmVP)|k|tO10M5`?S6)OH0R7-n~okL!52oR9tc1"
    "RpX*nM#pMvwmIrqbyB|b_h?qlH2U;j<(PdbI>yj@d34VGxl-ywc4Uw_t8*o)VbkFPRCnEJt?g*OtD!^WthuC^lo^%Z=GL3-Rb~I="
    "l&8DvKFhVntW@-L*R(p7H4RI&o>O$SlpKaqtyMpa>UK8oJSHkS=$Km__3p$Ewv)*Phf#_zvBzF?GZph?TC!=V#z#%lWtz}!&?zZZ"
    "LUP89-lGk1bY+Ks`MmmrY6?rFl9O$^^-wD2C_x94Yn;Xm(}HabUP-RSV!Ek5aGlZl&RD*9-g|54o^8yb*b*7O<Q!%mb8=y$IYT36"
    "Sf!HjSlf9UOLJ4z&efDbli}{{hxk7jqUt<U>LzQGRm;ssQ$uE4LT0qIpQ_X``;1r|!}sB9%dzx`-v#B`vs3C1rpVATRAVS#ymPvb"
    "G@}*Y4VY6aQzoXJ!=+(;XfEc&33E-g(crUFnh)9F2Ab|vGXt(_qt_whVK(VxMw>AitsGXb#!g#@_d%;thSEB^+3!wyn>Wu-dGo`J"
    "rf3`IGzv3JHFK((L8l9K;G{uLR!2c=d~nX=y(MIot+&P6qMn}knA1Mk#DPvLo2{F;Rv9T)pL;6B4I;YeV(Qecc}7O%<`iR#qqSZP"
    "mbo9P`+RbKOsF4Pwe%4`O@x#sU^||SWzBH86S=imWs`FB+gVLqhp4a`!`MvDP2ZjSF7^Dhp78LrKcP1~Jnc{D5f4vmKX?*Co4Mp1"
    "y7MI5KIxwG)74CpagJ{DJB10zyyS}z$fnH|RfnZ#FP_$YV8CXuSTgkJ6lo!;IC5xnq~x8+g-a|Fw$VGCO`JZv;F7VbbNXIiJgxuG"
    "dSYz5(PPlV7IGTJW|9nT6_Z<-I+mG7r!$5eZj3f|gw%rb10R0(uYUm;AE@C6?o(gPvY6$kVV1=gi!T;m{5JXGI6?8DXIibcXp>@?"
    "N^zE!TH))GatxFk*5MkO&`!feJ*-OvUbMPm@fa7dEMU0@mX{vMa^!_u*tp|}`<nL_8-C!G#`lMx9}a(UAJN@0KjWLS7d<U{S~EV2"
    "$QF_PbVRnmX@S!Mr>E;?Ps)|UlHxcly_W6WGwwcrd#6rk{j%L0fa-0OI-d6jR?wcbe*V4w$zQwiw28msb=`}~7L_e3TU55FY|WD`"
    "+*`Q!YsbC&SGxW^LH7CKOIPotAA-2ss|EaBAGq#%9Dck#O8xCqejWkMEw<e5c0+?tY=g3v6T_5`AFokcAZ9l{irnoEFK|7+H}+Nq"
    "<u<?r`usxgGbUG@zd?=<eg{`wb7f;u<D$ktgBnwS)dGq$nhptA)NSYzr&TeKTU$(8>6QXiMUtQ73GGPE13I(lUU-Qb1DW0>GUD*l"
    "*ak8-NKRMMxf|0a6X6ZyC~__bNII7gAyZ64mVmWa5zkL_VoKVXBWqB|Xf0V4{Vhs((Fg03L79EgnO2O~hD28Q4ca{4My3e_nc6Ff"
    "G3Q$PFkXb2%kEm6YI<_Rw`4UaIlW4#;3Q3=T$S`2>Z|17Q5RK<t`QFFb!1c$&B?I3ZO-dzAkuD7K!wixRMd=+1xW0y)eqF|2{}Zk"
    "M~=;60_(;wbAXG%#Sm;&%^>K$j~Gqxfm}V4%Hu%29lY#G>9@#11^AhAqDO?V*)%IB(#dwy6^b!wTGMHc(j6@xaDzvsqKN}6iTN2h"
    "Oli~r^wKBqn&?qLA625Z2sZm%#PqR%%n(mDNy-5R6O2gFkH>oPpHG?OE}P#!?*4Xr^W(H}+F(3(gsZ#=k?4OYH>CaRelGIz`Sfb<"
    "Z;vVPkpMl2zNHmQEB>~$!ps<3)01+w#h5H0p1{Rnz&&c|0o?L)JHS{fNgGFW)IuaEJrRUl)(pd%VR&JN;i+7<sC%TSQ$2d+Q5e^="
    "(Z$v_OHW=|PiYh?&PRDS5hVIyRE@!QYkMregk1JXMcloLsVS*~@s5hho8Iw%v~Ajs&S!9_13OjvXM8Y&Q!`R2eVIbreyF}eXDZ;2"
    "k&3Jv>m#+XRfJP<YEDX2MV(3M*X*P-TwU#fzu`Fe@Rb@fX3pSD!};l5qV%hodL9mATt?5WWj9l`GZR6xyOFH7lOmjvCBEk?H71TJ"
    "GaRNW8kngU%E(%4&Smsbpb^c<lkP5X<v4WJGUMWUh}uS#{9=Z+DzTX17i9)Al5b8X>I#aSLRS=&<i%`*>Z-*<en6FT$i>7wLW~Es"
    "&}1c&etwA=a&R3LFBFn`_F6y&G`&tK(<EWcY<lR31eFNYnN~h$XGS7d=2p!3lFVR(rFO2?R_l$5EmHB$;3;fINZC*)qnN$~Z_>=*"
    "g0*l2N!rQc4XOS$X3$*0bSfH!dQnYLgoP${h-khqGo>+2^caFRbfv)0P7q7w%5kl~#ta#0p|nL?D%9Zzn&oY3Gv{n6jwuHf(xGE;"
    "d7#gQBwxts$cXVEUjG4R09{&484aJcQu1agqM?xz4Ppc8OjU9o1q=A<kr5};tEtX3WyD`vl@PU~&k#i%V-(kF2tF%~?3mF40)b$d"
    "LY+RmV~`t~i#)(Y$Yw3CVhFV^t~ISsP2*uY07?vDK!i}A<cmX$aGRcnW^g-R;4qL8TSuzk*D$2V8dL<K9efLJO>G&j4%<!_hetC*"
    "qFC;o3K`IwBEg6~mr|0hA-{zoHZ+AjfdE7k_O_JbF1s*X!^!9{r|LB8t;;njSU?AvD}l($oGCuT5RYR4o52!UMh$1`kO_gDghyb4"
    "jvp{`kZVxIVA47uCC1OxX1wjM%=goqL6nmZpak^08AB{9018L&jF!UY^p;Ch44o`on!vTs*$%TiYrcQY_kWf1{jc)asg3hHQ`|=W"
    "{Wjf2WsAywER|J?x|&j^UWRVWLBJx~9;nQe>Bf~=$aj!Q_DNAxb66Z96X&V$sh6m1x}>3)NXDjK3oVc7rynFa*C>E<1H%%6<WWcH"
    "FO!oTxlae{CNP!1FqI)CF=$|{34H|0NSU^ww~9)$#;kzI5$uSLEX<#RHusQf0z3WJHIqYOt*tS6h`2|YaBseO-3we2{jhE1j%IKP"
    "cA(0rNOVvR7-@8>BY&B_B0t;4j_j4wB{k1rStavJxIM!+RPETLkDR;mqa%=U0zHAN9urjsP>LIGZ0xYU$~>TrrRHRi-y!F&Xnsu5"
    "K<2f(lI#qjWLNs+GVmU`a=g2K(TyD*FESl=PSj}{)Cz!D@H0#->tOY16bMRCcRntsZ-5rAt|`9&%C)g$f!<4?_vWPA`v*^3elGD("
    "75+}x?<eGt$%|1?_{*&jz%3%3Jw~LnQswKzj^VT2{(1vXY&rhZ)&8?E$K3qs?8t!Q{y9m<xL6#xIPfdxK&4Gbd_vDYCPKS+t@A_y"
    "Dk_oVuzkw%8=2HP?+Pidkr;~yk!EtXy~KguLLS)!=R}yiZ??%AAL&D7P%r>6Mq6D-RB&cT70At#G*xV@eBw)Tpz*C{M51($0Cm%I"
    "Hdd5a=&b9|AS%9WC8*wjHf>Ty3Zg6{jZ*E`#euU2fX-E$vPOn=5%Fm?$wVw@P+$qwQwg$tMa$`D;<qMRoqD%keHjkqP>(`Gr*X)<"
    ";B>{es2P!o?+z(nDvo5(K{T-I=I!ABaBWepHuoj>44ayjSl)V1X`u^X9b$wb)3lUPj^R@t1W?$IXqXwNrP^@O<6^$NI)~^}@www-"
    "j0~^_sSb*+U_)`fs>5D?=-d&By&7jbe%*7BfFJ;CnqPL$a4|`yVTm2vO;l>sW_|0Bm~VxV)?6AX!nVZKnm%b}fa3IxYUIJTfrXX}"
    "Ef-q;xoElW?q5v!=P)69a!?ZEwJdNsOX9Zxjh!8A>q1wArO_Zo4y6=l$OuDa*vwB7*4pLu8)d?Er`Kr%TDF`}8#QZBJxuBr++Zf_"
    "qU&B$&_J2UU58k_myJ=j7Uaob){;_KcY3Wmy%x27tvB{R<f#Y1`NJ>%TU7P8ybn(DQb!|VC7a4_p+lMOyX-DjC^dW(WwI%i-r`6>"
    "#csMsSU`;NU~Xkm)mJdnW|63dl}&NhqZ?ds3eA>$*!ymE=(<7|Gfpk*^3ywumoOUqpcyq5vpr?DN^t3lPG$|1MY$tzmfE`_q$<M`"
    "sxJf+BbZH}RR!;LL7i-{K1N#>vn^&@%=Q+u-A%XMz3JsHwVm#tc!DLjxN-mPmjfRN4cyJLjsBMt+zE2dA3)e*xW#ZkAH!MM17=!5"
    "MS^j9kXgx`uE7E*4cR>Q5y>&LcG)0rE7%1z$&P3rtg4IQz9xn%jDkEl%lcBYGmH@!mk|}TOwYp#Du_RF8N)<{VMCnR6z^>qw7=%v"
    "p0AcR=e)7jQU?_%x0TS9<3dWcT{G57CZLBk)=aqx6le2k4(wHjnc6IdTMV}t?r)Ld*1G1Rw;!T6Kjm&Wf|F2ho{VMNAjeH|r>f{q"
    "C`ImdBWg=8(b);Kkf~;phtv4^n|pf2ddS3jjO9zWwaPO!dVx#&sQA2tNAz&YQ=>3Em5Rj;({(Ae1!J8DifkZgY;%3;_0;kOSqrk("
    ";^soDg;w_ukxW_}6@qg~cc7`waCpq4@=6}$*R;=Gk(&v&W?R=m6_VmqAVwia|K_)hL5Il=i=GZWv+NjhJ<44KBtosKX>-OgLoO|o"
    "rB$ZsK^D_dZo@UvE@oTI_7<~+F{1%X@(3V{272bei-*Sp3~e#u3@3ets^kfxoSg8>nGrB~4!f9bG23FcwYa$$ZZX`ew}L8SWVAT!"
    "98+EnBa1O{5HB5V=t*t>)uR|q3QMg;-E4*oGzl%rGXs9>3<p4wew0;Q8G3-kX<vall?FL0W&{eAj8S{KF`Y*`s}+67B%9&GVz|X{"
    "Z!sLdAJzm{41eQY9=f8Jvbocl;OU7AvzF|2qbQ2Kf<nO&9P((A@!+=A#c+$^7Q_7wG2D@O4mh@3E1V1A)*Ar7<o>jUTI)@H3$+$%"
    "E!4V4t>0~r545;PoBj|4(7cK`UyKtEpldhV@_pG{$TQ9Ua;AF3LJOuAO#Lmx)Y_T9h-wklBC17Hi>Q7%qB_RgT3%c@_0}5)LP(ZO"
    "8*L0F7;>4sbuRVMN**mLl)VMnh_5Yh;@pro@phXv+HGPrYi?>0+9I^q2~BsX#dXGHh;I^RRs}!o%$e4LypYlyo*$yJwke{D&1$b~"
    "b@D#QK7V#X`^hNkxpw~Zqs;y2QR<T6?jHntJ@#d@eVp7*`AgE<W_wbOH}q7z7y-Eb_)CiVoJE(cE?NC~WVIOW#~=mI(M&2;9z+1="
    "4j1H3b8<~>dPYRm)Ddc#inIti$2wacKCDL)ELmN$`qm=}oRT*Ls5&DTfE8V5SmZT@I#jMzMgHT;jcVE#{4n){d*tMC>IW}W{E`zN"
    "9XX|jO*QojReS3SVMK~>*7-aQe+_wWs`quKTyx_WCIzcQGNpz!@v$a8zTCveR|#*&FkkSt;Oz}~>rtLY7&;LtcgnTti7A-~aVivY"
    "BTN-1`Nhd|riyV%-Xo_HK~^eJmlnJ&czXffo;?~<F)|HOu@g547Llg{n5EXkgQ=43LpNlqQyI8yRGLP+syQb6IJ{enEQ>Y14%Ybl"
    "w}k2uY#d+L^5|_Zw_5hoV8-KeU?IjrjGyVT<4O&AF$)AyiMAR@@eO&5k%Ca`5h}nDC^ab)M<qXL<%e=6X;PVga97hpjD;A#wfUiE"
    "FM6I{bp}=*a%55;83#{lHdXvABY@bpTY2XteoSYO-=e&C0!z)e^y)4aZ$=cZskxZYARdM#W;^|?bhA30hym|m7Rwk~6SbP7&?R}("
    "atUJr)&i^rSid&Fs<$s1Bz<fr2(({#weadGUbPUcZ=q<bQqxmYVw>cPBT*Bc8Pf8_f&ku;7iK}FXHChalqNFoUVN(ywB!g|=Su^3"
    "Y%|^FTpOq{DruT@7qzVID>7~lPMJA0X~*iKq9gZyNxaG-N9Wv-#~Jw;Qg%AnN$x~ULndENdGD@vFps=0&0C{dl0?!g_&M~~g;yaU"
    "Xz014?`Vql3KyuVYGZPTsuevCGb=3=&M-4_QxK!0L$nju^4l|FlZRy0ba>r3%wy81XsOb&c|}JXM*vP$PYA0T$d+lCDt4lxBeZed"
    "G{1;#5!>50%|9TL_xDexl-DO8km3DFCq-0m9kL(!<OoQ+v%cAtkJsbCYcJddzuj$idp>f0`oN;GMPok)jmd3UiA+9f2g{rl=^mtZ"
    "eZZVbHmBOR$qF)5j;gXLQma@8xw!}Z5{>m4L=VVODq7_tpNJ*P6I+xv3PMO^J3_6LsVXIYb5rZX!!Cyfs`QtnF+=ZaQca!@7>g<-"
    "H&QT+*1dEcMv_<B2GdE(pc<Lq*Ga!~gRy#RU)lRvVzRklJ#Si)&m<JSM7eJ%j64xJlBLE(Ascy(HApbvY-}z2WU^i~_LRnY6Mqa*"
    "x0a*^>0RUIaBM+9k<K*8A!a66iS`EGUu)=%wu+VqX)PLCG`47L(b%G~bp!o+8qr#MTwBxss<|=et0^^x7&*R%P`F&idIl_@Oowb-"
    "k2A{*>@aBtk2gYSHBqJ1G8c_48e25BXl&8gqOnC|i^dj>{WUa(iWvwjBUuqARXz2reT#gyR0o`xEc0WoLMDJ)MDK_KE3c5AJu1Cu"
    "Y|+@Fu|;Ex#{MQA+fX!sq%urHekVKVih|oDIn8?4o0lgzbTG^tg)R@@fHDNe6U)`lFGOR}MjcYj)hh3jFD7bdJNQLHauW)fTD4l!"
    "RKs-zoFNm@D>8CGJeq!er80Ec<Q97^z!xdkq}dyZ%aIf+8B2vajc?8cD5vF=3i(D5WhP1Zi^dj>y+vb006rj4gtRr&o65t>3mL7j"
    "R-+L|EWtK)WHt4ar#GbRTSb~YBKu3wn2LyDovsYqb0t(&!11RJ!4vW_LYbCmPzo7~8!)n&K{2kP^3yIFTQs(4Y|+@Fu|NCSltYt4"
    "R0EU3Xw9o6o5p<eO}4ActGKc=N#6QaTuV?+OV$y51bQ{5<uy09Xl&8g>omp~s9~IgN6M5flLj|%rlE0}3)I0^G)$g(0^0;V5Tp`n"
    "GNnaAulyqW#&Xh@i=31xY1*lM?-mJ#C#57}cyNKk`!OkuW)Um-I^w7qWp*6CXl&8gqOnC|i^l%!UHrA91r+M0DKNmyt_lCt8=1@H"
    "*-0A2H?gVZeZ{r*?5DhpxK&+JRWCjjt5*{|q}Hb+sZFqe7`3C?AaW7q{>45MIj57QQbLyGZ5E(U0|jcIUy{ZetU;&w2s$!r95W|U"
    "aB#MILk`rD&V~S+R*|Bveews*B%SrH%hyF?rnOY-3`h-~Rz7QTCP}c^3YgjHBgUL51dkFIZCww*o2a+U@x;1l?Ac1CqN?$_s3goa"
    "TszztQea$H5U_;gv?2qFr3IjJOQm;5Wx{paVZVx%%2H5sk_-VPBv+94S!%<Hb@kFn4s%-NgRQDkshO@7?nf*$u&L)oV~fUq^E7ri"
    "o#a{}n}uQv#nz^=H8Hj(#=hjHv5J^6urWs;ib>*6oT#@v3=QDP)lE!8{X+m!7@>T*d+(tfKh|sY*2LICv9}*c_TT~WmpA(z-yIb5"
    "AoU35&9;21n~yh_H@gQ9CqrK6=Hg}cx;yIpB%%ww7J4o8TIjXV>o<g6BjGfoa3Y+n77&DM8=d%4!y|1ol-9cm^0Yc5Y@@h>gvSOW"
    "&j@J?y%u^c^jhe((Ch1aEl((+6cteHR*Q2ZXp#VWkb0OEVK81RKfTS0TxfJAcU1=ok!@SCZlTvguZ3Q(qn8b3G*xJN#$sy-2#{@_"
    "IwnP3=P=%t+7c*ZxJV}t3(lU}Mq8Z4mRHd$b}u(r#%SZr&89F=vg{aW57q_#VX*lp;Si8mj~b1}AwrBjj0ZMY=(W&mq1QsMg<fA8"
    "y*%|b!5JvL8+p3{76HDHxJngBm>qc1@~}x2<VmZgYExQClXM|k@)CNrp$OSY;T{5lPrS-bFVz(~VN~^w#%L$Elxn5cC&XqQiEQ3y"
    "dbpGK3!s-OBWqP{Yc6%U@zW2Twb#8wVG!?Sb4sZg2T`%DPZII$pbZ(6G-qBzuR+GpCZH!_hLFgwB4{4jt$m=DGbC6ucZale8zC^~"
    "b(S{-hN69Qub~$giFjzE{1_y2CEK!QNB=;%)Qds@G%TH4Yf5fkn<jQBiQ|e=wW_z#D@Q;x`w>R)C683)BDvxzM2B*jI=Vc56b`2q"
    ";B-zUm|anvprU#Kz2FPSpv&#68Nnf;=hUoM#yOz_J%#y!0+TdgBI4U}@?3^*2By=$^(VNR5Pho|j~pf9jL~%2QAy8r)GF&vy>ZyV"
    "ZhEL(eNQRbt~>ah#x$>?7onO8USn}GL1f)x95G@{<7I262bye1@<1{=P;*C1y&2P5*}WOdTj(`?ga;|W=p~;q-9uWQ2&ITB_!I(J"
    "8|4Wm57Si05$h@ZI2$J=%ro?wgG7=TrdCrLhb@$|k{~R~ZKu%an6RSDbr$@MliD<G%EtGUfznsd>nC%qg<cE27J4o8`m*R15oD#N"
    "imfX{Y3wO%t?AiOp&BLG+&ME1)MH~A@~WSNWQ6RdGT_RZ^;)xDYu4)x^a8x`Sxo@xQgH4HUPCdU0_5Sf!WYVLQ8Xyx-Eatp&M>M="
    "9;=PD;J9YJ7JB^_(QDoGxajK#A3<Tv6yVUVP69&mKPoG4EV9W33Si?YKtn9nTWgfeWQ{SJidw4#h%Ea0s$N~xyw7N&pMKbZsuySK"
    "Fd_rCqlg8Kaji1E)&y1M9!a!8$iZn?A}{)SN?(aVnQ4YOhi<kg+-xds3_Y!!%-WiAOMFWy1M~tf5DI!alD8?mzUJsdN;F;3DU%3D"
    "i>(T0hK9YJuE-0)15F3YDZIlbQ;jZzs!8`&f`5y?hCCmzkq6{DU^PmxVwwpCQzz?UO2HeI%A|QhrUn<$dMy?cPaccDz94-$c~+w>"
    "qib?9HFRnQmgf`lJYXf&)F5ZaOos2hTkH~xvUExw2TVp^H$8r#n;wsmdw#P$ess--EgpNm2h3{+6Oevd%8K&Zld;t>MI#;|5??Z{"
    "4}jdRMdW4)KeTtiMnvU!iN{bI@_^}}lcHGD<N+lMA&r<FdUllDiLwW!Y7EA;agZyYMy9>_MPKYqb|AG(DIb-SrI)Tl(KD+#XCYyz"
    ";IpX+Dq;plMI9>NTQAF$wcGr4@ffxmMWZSKd234AslAXpQ?`?IXt293kTrG(*AS!%woj4gVN87K#on9%yUsW#T1YZR$T?f^ZBmOX"
    "dB1x_HHT~{g!q+n+2I!Sh_+m?>Nn0~6I7D=WJF4tX%fRC3xe{{7sg*^z*+)$jfEAA$_&;V6W2){4pt_=#$&JssFy1sBePzf+DYXB"
    "bYa1YCwuFGDjX|Yy2YT%L|E<|(R77PzUXXN5-~-~i5gNuD@jwN1xF~zvp3|yGex{tLl#g%%*72^y47{qhT+oUu{9g^`fS)+%8!uV"
    "&ww59hJ(P19ie}4`dc{IY)@z+(zzXf+W%gN;3GMa7LK7OX_9tsgXJY~dmN&F+2ZAGCWcQIw=HgagWGKBrni|???j7oW9ruQ$dqOB"
    "XzgT(88tOgtkduWY6$Yk#)z(_ltx|iXloU7tzy3M#0uMGiy)%_;%1^CaZ)ZU)Ru7Q9zq!%{cKjJmgJ7fhLL0`lHk#%uT{)7kG8n&"
    "&3UvFRGcv9o-UC2TfTUVCAYY-+3v2;N)b}w1EB%1tPl<mK!1bZN`u#So7d>=1UcsqAneC7+`_YkXOHkK0b4Fr7|J&_oQc*E%<{-@"
    "fMT>F35lEnV0BAHPL5WNB#%%x*HwOTlUZ>@Zy?B{m1lI9(JF@WsW-AHIVXiIdxMd7<f&(0y`6r@Q(zTZ@<2Mi#IzcD2*ogJglde^"
    "Q-zeQ3eILpNN8VzQw{ldW>dhp?Cp@fK*80fzP9%snbb*}x&}tcIvrEc42*1zvc@L4u>kEDNhGC%@Yb0TqtR1drPymI3(uY{a~kWE"
    "h?{8$j&>q@42~P}zDYZ%jer}Qip;&y>&oS7ml;z(qVdLj6?o=?^s!~5ttx<6mitf|ab=bFI8r9C=fp`n(l6DIF$MguHMZcbY75U6"
    "p8X~^nJv6pc=h<v`Q$fS6^v1crx0};__Vx>vCDRT!JtfZ)#S)aefkiBDL$oAou^#yFX2^gQ6<E~YY#XD?@h?X@flKogdYqEwSX$K"
    "BFU7&ZfGB)2d@HTq~n*wEAXk;Ib@^EG@Xo+lQBJ5W#m$FggKKp&64)PNh5c^MPzD%V?lP$d|h~za|DCEiS$fX)%@%T3)YowhP~K="
    "oib)hHtLyTM7Xj`4Q%ML<-9MvdiLZBoG&S~$)udJ)(BK+*1C}Mu#C-NrzUU}y*ymP0qh|pFMdOX<I-31l5d;+OmaW3k(Zyjs1p}i"
    "9pP^R0XRi<C*iHCmofBuazv9Q^GsH-3$GSl{pR-YAERllJ}&-xYZw2t)6_mfEY<29W>mFMjwVZFMHON&1N!pGy6VY6y7pP8Y4V5)"
    "(q3Atk6)I*$XsQXPM!u}4Jpisq@WM-T5@2Le$<M9`B<8~3r3d|ib4JTEW<kc@_EhA%yn|}Et-WoM=Vfh#iQIrJIUSB4Vf%$FvN`L"
    "XH2bIGsm<rh1}OW)Z)5l_h!a8YEeV=)LJyUX5C}0lo1SESGpB9YrB0TeN#YEP*`7X9H82W^VQddV{{c8LtsLqZj#l&Kn#ZwtRqAK"
    "MujWOWM?S8!`{s(huh%l1Fd|M>pG*Hvm_4+FX&LA#(7$$XR}$JUK=D2D7>v3hvJSgiXkT%pG``6y`b_d;JWE8f$rlduu%*0VpXFg"
    "pHxh1sXQ7=WXQsPv`odHbO+4kIY;ttxd*Scd(3q|3oeGA0~i1K5zZ7*^>##o$9vqa$G&W~j}?DBV9lRqr`z)|{jse1=+Zgj^!<el"
    "{X-Bvkk1{;o}VsZ(deSlr!<P7jZmB=e_N6vDchMOFSN4)hR)e+73d)O!1ow6I#vCQ<f9~SqIvNZ0@IPQ5s0cxRWY<Yrre}RdUMU^"
    "nZYD-qX{1I%w!PKh9m1~1aAV7`AgEM4dgL-p|pb*YedONfP$VLeXx^;vdRWpht3`Omp>&A-$Mf3lJQ^HY+&MQtucAj0g@n#@^n3U"
    "vRs)ddf8E)J87Lu09p_`??CnxL1Lp*9Y5<mrO$SmRhhNcx==rGZ7Nl#f|bXKrAgI;I~d3$%vs<k6nR?MB?Dq@q--BNf%yrKQI%18"
    "p=aGqxt{}`w}-u;0YFe{4u-Po7M(nu4(98!CBI@Hd_p0jZ}FIxM-)cgQXzms_H96nJ!^UzOic4|BWaT-mDv)F0#l;AdlGMql`yf-"
    "c+4~8rneeWq0CddhiH88GfXhVRZ2%W3wk*_R3_7S4IV0TCyElb{0eyNw>BX*OD1^+SyxWc`q}dA)Wo$HnPR2*ovk~D42SZwS~sHZ"
    "nZ!rEK^C_21;Y8=_N<&V_9zPX+q#gyvyWqY1KFSuSJ#{G(YjkXI+M?zZ3o)0E9mw9^0c80O?{v=Z{W`1JTGC+v7y@o&JP#5Zp2&="
    "^Yd)zN5T)3qUy{+HcZ9fTdW-o@VZuKylI|<C$H&EYElh>1=_ZWwngI?#4L#UWgtd%c^0S(Y0BH|Wzkh`;8XIzyhcHbXh%eayq}b9"
    "7&zI^!5+iU*=>CF<&JUKP-kyZn}WC`xo>cUF>;iZ_~hGU-14Lw%@1D~MUz~NK4e+9S6}uP#|1HKv2fkuxE>O=Sm>vCL~E2BJF-Gp"
    "8;K(q*~O||s7@9nl*E0R5QlYSs_C01P+B*$luAnNYk6_qg!omwyO9o~W|LzSSCc|PM*wAf)dsn#z~Q?&RXt5t_`jolH?<XD<k;{_"
    "Y{Qz<Wh3{n$PPsy5a)M_;(}sECWQ)T?b<V5mBR`{NOvq8m#1@1J$L}wTCQ7UwI1fR=8zUQ{rI;E^)#YZ1V0kd;1{QwrZSGn713s-"
    "Sb0B!q3rHG$bE<=n%QN_-a-~HZi^4DLoy{9FsWCnRkF8|m*0?($zwAc;*HFKG>}oXB4Id#ps0~sG2;u*AqDT{A(z%0*^uH~o<WxR"
    "WGj)0E<q!{1aH#JAQNe$WM6}mSB|45ugxK8u3$P9jS9B97J8KzzF>z4Px&&FyfP+w3_%;ZBBt31W~y8{uJzY=jLhm)68Vz%2>DU-"
    "WF$z)Ia^a1EqD#?jlq%BqA#iEf(}@;%DY_p5Ac{XP+ZE&`dMoSqpdvIOy<^1YRW*(ip)O>7Vy<W!%l=H)tRP@_)9z{f=ZvEwJ7^+"
    "T&oB>oIW~vxP{S?^=!z>W5~-5;n->55qJ}2uH{wIiSk}24Q9(@O&FS#EpQWx!bz*iV6N^8F~J+bk=z414LIO+XmRZJHPY#^1{HN{"
    "PF{V3pli!;b@+a|h_)pkP-naXtuk(a7od(s-+&7Z54=S>HZ+Aj;f!EvY2KQ^1-dXG9FJ5-P9<;L@z$a4s)nTH?Nb`2Ds!gzd=3f6"
    "a;TR*yoqASqi`ckkdq*fwg5Y5m0FZe7lTRbNSGd8ug!SdUm+cN(>J{BQh;}Kcg+}LS#_^)1TVMWHm&F_mk69#06?3dWCu+%H0~Ga"
    "tU07#a1M#CTwH1O?NOgG(Kr9LlY{={7L%Uz^B<0scHooE#o>!Sj#x3;jVvjmzz1DF2ZTPI?diwaDDAtm3qE_sMce|^mFz#dMW0&="
    "c*qg`{N`%6zaHh&6F7LuGRM|lUuQhEbbh+%^8<dIbJgc^dFS=wvYuaFpPw%79NydR<nraGr%O4|o*4E=Gv+ehUt+wIOSS?gJ@&>Q"
    "W%Zx#pdUAWGBmrF#^#P=4@3NTEMz79>IT_s4BW+_t72f_{}zo8NuxX%)3g76^M8*0x7({vXD5^Xb;EhP>Mo;rdl~1CFXK4MFOA?&"
    ">;21m%X-Ut%X-Ut%X-Ut%X-Ut%X-Ut_ttx>GW?OYJWV+~HXLQ!vzhmDcD31V4|{~Kt}pvd+eo{&ll6CH-TT+7&BJQQPg!#Qpw<7p"
    "(sK>P8j3X(E4?pq{Eb`hciRUE;QZq9@(=v-?5cdexGeq9-FBFYzYWn(<@ygdSF&hK>o-kS&$qImUCA9~$}KPLqHz9$$z}1r?DyB3"
    "dh^<SEyo3=*DZ5<*7M_|ln>W<ytZ2--5Ks^;$?_sh@Z+3E3quTSbVV@d0B5+Z&`0yZ&`0yZ&`0yZ&~l_vfeuAw|mekI@kKb8j3X("
    "zuKW#+iceq=8Bs&6kpF!to5N~h-HYCrIui<p;(ps3Y|3+zshoP4eH<O9KdpqRbQ>LVi{r?Vi{r?Vi{r?Vi{u1%B@APWxch8xTdw%"
    "P^_U?L$N4f8Da_kx}SQ*(=QcI>rti4ct5l8RtPTMT<E`sV%;ya4q7*at#q?8|H}Mp9^jX}i+Gv%E8j=AO0H#yWr$^nWr$^nWr!uj"
    "YwmMZz-uVhP^_U?L$U7EUE{S@aMsk#sz#O}mLZlQmLZlQmLZlQ*38o?6jq_I$o&_cKL1-j=wIKzyV@xIZE0;>?Tf_xzwP9pfBDIq"
    "XoUXmCqMf-XdSc;S_iFz)<Nr_b<jF!9kdQw2d#tFLF=G(&^l-xv<~_eOf>$7OapFr?>_wdyLw%=?Yr}b6N2wr&t6;SO)N2`?EILu"
    "Ph(q|y60Jv8_vXPlnO-`6>FHqm+17!Ar+P1y?^)Ud^ITJYgaCnQu0WqsNTy=O*L(YX+DnO>(n}M5@VI~sjKF7cEcxMHRrpyQu^C("
    "K5q7>S@6Ntzq6{kFkA^m71N^Xp%iO$Y|Se_Z6C3@k=1Om>0Im##kHamzp|>&<WDF5AAkS5|MK7d{+myob7nhAsa!$PvE-&*4=HM&"
    "M=x}|bPVHEXqqdwsnnQ;Hx`@ZlIBo0pU!zdi+g@O+Spv}zuAvZR~Kb}n$~^iT+f9*hAc*IE&JY0qJ?U8cO`n4^EA#{KXMAHYD{BQ"
    "%2o5H2m8FK)0w^YNrw=9H+>AQcUB!OUD4Pe#h%izp@*ir&ON5yg7z)-l%qDCCQfI5G>jp*99^r5k?%ugS6%Hoj-Cgm#zM{7)T37+"
    "rDQ|)wpV3Kt#wr8^xZIi#O3z8Z|km~&zp;jZ}xwZ<%!v6=h$owu2J!|K1!YR+O@6}0~T|iQ)f<GaU-v%X)3i|qq1F%@#O67ayu_J"
    "ZNJ%mJl~J&Psdg;bg;HMoWZ+PZML<TQJR}}S{Jjyzq#08>a4*Oe5cznt*0#?RIATgx%zy)`S{)b{QGjf;YY`2oHnM}P+GJ^j_0xm"
    "-htz_GBjpP5@F7^K1@j2hiV8Ux*n4%vCa6T8T@Ad`TX$Bv4LT$YR;LQX45!n#%9yClruw}4dGb^@#ts^lj8L*`<ylI>P=1FKWX6b"
    "&w1IOUu-^YPHn`f6!!J8dgVr)YIM&Tn&b0gjc%fetrAgW38Ii-jw8{(nx?@)Uu@&!)y4TnRy6mcAKSrGCLuSK8JQDDJ5?G{x!Eed"
    "OSYh&^p4Xr0Fg0jL+565#=CUR<+XNBLtZd8dBRQn(B_a^@PouvXJ>eWuOoyO!cb(1VTtY{G1-kat`d6l$>}%S@5{xepWp0fdNd@M"
    "MIYSVg;tD8Txu!J4o5J18*n=^TB6;6J#);1q}NN2<g9|Tt0(Qqs_cXCNV5c;HL1q;p|Nt-iYT;khFIi#J8`8%()Kyjp-S)5)=Xxg"
    "Q+Yn^#pOX5{`Yv)12dw|q~)NUR>=@)B$`G>FUhn@gkWvu$@1ip#PI7#B#uxU!Ee=k>Qwvk@vywiSf5{AkGc8Nv7K%RJ~MSIjAOL9"
    "Hydj+Hfn6%TMkyK!cSY6VkXAPdwTBz1C=o4OYK}g7;zU=jA8bsJ$m4q8YHz68CFe4W{SpntF;~kPQ{~DRB1-vLakhr8!w*!Vm@fW"
    "`&nBpuFsaM!wjY+MHbh|s-jJ_CCmS5Lrv0or=4Mw(k@0nRkbg)@FXal$YU-&aLt84G#M$2eFSGv$eD;pGkhD7U?WU}k6yQIi3wCo"
    "m-0dj+spIaRY4?<qo8rUY)G)G2J6Xx3Zof>jZD<_7>z+`Xhj*_k!E6PX5v<)V^c$zFSKyEz4&}e=RU<`yG<@>J~R5LB)b~3%H0|>"
    "8_5Hk;hZTB-ED}u7=*+lOGT;r!r8CK)j&P_`6;)b+!mbRLI)CE2d7L(W~iO~P`mdPI!XN6B-i3ZG^QRfitVvy$CbqXMpMTYtS3E_"
    "V>yEv*75%yNl!WUfOz6(wA`InQxWhuaw9Sb_mF3=4ZV7yg?*`yMuQRVo*atOxvcT6Y=&zV_&}DG*rgN(Sr@IR6FDaz5Pfa(i40ji"
    "Y2s!}BOkHV!}wOU8XQ*yyCG;XG784Iszxd@Obx&4s0AtBkfJQHtzeXz>h#goyEbn3#5^RNQg=A-9oO_i*JB`<Z9NEUP8IhYB<p~i"
    ")i4Z1r91?wMsz9GDC3WH6^!X$Z)cW^-5umuj6r(C;dNBLl3EMcVY=49CaKGj;)imE^o6e0fL@V6LmUR6Qo6m^%sA|Zxa&!6Tz(^W"
    "q!e=)1OJ71^B{9!&2mUdEe51k!9Jy1d=0k3mpj>0zt+U3n~VMC{POzL&S-dNA>aAV7{^Xl7c>~fTaywWBcy#)Gd87gUyu`|>O*|Q"
    "CadS0?VK9HFi9J-oOhu^J%nF(WL}UvYecFQpKLLn?%;BGvPpz(8`Bp>u6WH}r_*b$jlO4zY5qr|%gQPeeF0Lin5Tpw#|tWSBS=!w"
    "C+7i-)=1CK`f#x+J9wmx?QY!eOu4gGB^E(d#=}hppjS;6s|c1I(i0CMb}z9JyMsuG{XmR3>__By_oStVs0gZGUiaPkj(@kk+_wq&"
    "4rPK@#DbogdL||Q3N>dqG6e9M2CMgmI3~BHS}aNcV1klK#UF0-XR_ln5Iz-o%{NVO5;u{MpacuiDJ{%8sdG3PRUTg|!XJsrq>kj3"
    ";4we;);??IDG8sd1|1*~3)Gj95Z~@A`Z!zDr4BP;JxCeyb>Kagq=-n+lP=bcLbe`H+Uc8l*e<uf+rd_LyK#Nk6?JTpQmK0o3~)gT"
    "LXl#Ego*-z1CRhc(3O^JVniut7_|te+a|R~y9cpTi~BC_x7pwMf=a;xaGo#(P!Qc*kVI`UsdEgAcZ1OEuA<4Lj4qyv#~=_Ybz{s6"
    "4cu&RcK4w)3IC*vn8ydhHx^uS9y+3mkP=KXjpz61lJ#V0ObjsOZgQ7$<7opoS9kz=cB=;G71qEVPOX(r=#Wol4wT)-YLisx2u{qE"
    "`oWTyEKV14CZ<9#Q1`UdGr)|UPN`R0lk=bdVcglR8@d3Ck=Ya(4Of^(2v|{>P;>^<s9JFm1r$@xH@rPz=z(GhXpUDKdNE5_4Os*j"
    "p5z5V5g))jBVTdp37bPFr~_8EYQRqpyp@8LB571AWAj6;-PPK5jHD~TpJLQ=I%FFrBxE|O6kJ2?3cyL-A$&mE=q^hkA2Kz5E3dZm"
    "Y3xfc`*LSKXro$$o08FxRY-z>`s5@IFcewncsd_}Yc+|AUJRrgNPyt!-m48=kJ3Lqv7X1XYvb?Wz0*Lt#e~jJ?_1X`lo<`e>WT_J"
    "n{0=$PWMVvBtn(CK56V>1$%0N(k?p20Q-SYK1szT^F5IP^K%x+s*@CavD8e(5}AhF04Y$sfg?{__+K|0Dl^Fp^P=qcV|yP@b!wTE"
    "$h|sh0z+m&KXa!{?F2q$aztx~iVmobB)T#+`b{)zC=widy{YR#>LwrcpGjmNH1)^tHv4glj3=e=K&+KSlNgt-f&){yT*))|p~WGU"
    "FDVmk1y73*c*q=KQwUV2&${&|s<fR<7oN|}#kj}pQ`#fbfc1%xSCcvo-BqOaM#(e>c{C;MXEJyt<t?QYqYBWrIkO8gVeqWE{dGCN"
    "zPuPelk&~W>#_N`eI7@-lu89V2^_LRZ-L>bx!FqBMgiJYGE${Hr$l#SW{{#wIUJj&$4{DhGIw&4S8W*-0|Pk5MP@K4JW9r$8vHOa"
    "=^D>hT!m8|#t)5j&gGzzc%|<zHX_gGx)|cxyWL|JF1nk976{=2_G(g4rQm$Qg^>gUfM<mr^PI3S#_g_aiW3F=%OvNE%{`i{xtq&H"
    "e_AD20j{B_*&r{34}gdSKN-NM4CxO8oMuWP$yZKO?PrXh+iMNoYbz;}3M<*6@>GOMY8ep(NMP)Ugd~~uCHqxzLB_550l&b2*xNnL"
    "rl;AOd*41a6m!xNkvWm&n#=@dszqw_!S`eaoq|uT&x)5*ahp*HP)k9fsWepxuQc>vTIi%hUX4o0DD#(L1~bSzoQcAMOkqovC`Qg}"
    "%k3bBt}FP(`+&DaaOFuupUQ=7%Lndnx$(~7ETn-9Dau5Kp!z(M4l=;dY3kq#DHI<$_%U=`Gi}hhM86z$-qU7o_qLzQEbS9s$e|eq"
    "X&5sSURJ9^v?=zBlF|ik1GLd8SVT7)hJqdvrR9)$KJ@>smVUO1=s_btQ>H$YT14kLBzHC19gJE<?LI68Fa#*kACa08tW3Soxn8Yy"
    "P@JosxMJienDvNoUNa@Ar=!2UeC%95amw71`yWWo$Lq_Rt2;mDii<&h-O!x5m{6^x9Ot~BGQ<F4v=rVrhF6)iCRkK$mlccfj0m1I"
    "b$K<e%l>}+lQ)D-nW2zNVuRD90E4e&(jSha0EZY-fwmAHdYfYLrgb%JDD?h?*0!@DY~$h{vkNF~s)Q#QAaI>QgCq(+bEOg%q_~Q1"
    ";=^5$Vac&JrCGrQ`eUCG;`Zj^@%dE|0W30K6sWa|A_-2?iBA(wtXen838ogox7kbUNoKY4#2LwcPxV>mY;Q&8g><HkL3*jInu>mC"
    "BpJ3r2>et-X4**8TIr0FYh`=Okwi*i;wyP(5JxYx^<aMZE@TpECM2*L>nMLH>n3W&nD=1NFbV}g4H*CcI98@8$qp3BbV!@m8hM<_"
    "bWji_83Us6DUuYswTZe(lMrQ|1ziKthz>03U|&!gy(9A_pG$l?O?7+g)7@QG=f_m=p!&&FwFz3X)K|H=9Nbi*X`Fo`UC<{ZKWJc}"
    "YRGzq!KjBjtmvN>C8yhP9!MH-f{DN~&VXjR?D1RejL4;PI>ZixbXoh9<v5@{)I<|TQLpOy4AX9nB~xyf7dLykiD&=aU5pa?ZIYbv"
    "XRaL>AP5~5Gb%hJJX_&wuhPIrsK6OYZ9<|97Ep=im8PDsO^-+x*&hxUxST<2626a#%%B{OEJN2r=4Z)=DRr#&IYXVfDH7nzt@O+N"
    "`EGpt^k5=UN<nXDN+c`K71tq@K{aOxby*vbx{z9+jglyVlYm^Epbp?M%CpM!*wB3(-HninI4<mupVC&H#x-OF@kf-kk{Lro-Q#Md"
    "QqGP)vmxVy@|=vA(#!4a##K4wwDZGU)_oNmZ3*CcuqxXbTAJuGRkyRU$}C|;Kb<Be;N%TD1m0A)QA^(OuXGBQmS`$>UYEK<Rr-i="
    "8cI`3J<51%3(b(>T%`Jx=?@E8g%Fhrm4M0~p+j}Z9nYGP(?cDH40qQVpYd(#XWD|D=Aa0qG^N2Deek3<MGZW$Te6YTHz9+tsW0T|"
    "!)o8tRxU4Y9a^IFQ`xug9+Yqs8Uu?Ee~AtPUJvlCCo)@}&R2doB-M<OBebc&T9r-6fJb=B)4TTF_*Bm8B@LFlB#Oxz4sBd_$c`Vx"
    "NG5MYDFjI^bDE-R>4C(F-XOcClDEy2)sfl!D~%lYVBD7<^uii&W=2dAhYpsL*c?VG!GTe}41U`g20g+=)5|pY3w5v0?pY%@*VmUH"
    "rHp^9ZB*Aa22z?bvZfrUa_m6)5$6bdl6{mR|AWkW+N_XRS@<_1pvpfR{ukEr?qVmyIAk>y6X(bzwqAgENMUp@>vaj9p=?0$D7r9S"
    "fUn5uo@1u+FEw=iFnt2GUdLE*AQU*kPP)#*A7l)KZo%PIvWA+CftoaxeY7$M<131k&5I2jSMyG3ldPc~cxD`OpA#(DWeY{5c+wbO"
    "*+|dGG7h1LnUZAq0KwZz9ZfCtLK9ExChKzH+BFqB*F>U65gO@{A61+cWu6Ez+H#n#P9!neoMB9ZvlK>rp^3Zoypxh8S8&Aao3aSL"
    "mnGDoqsnTU7OgeZ6{vNkJZGG#3#dT7s<GG@!*kTUThKcd7=(k1LuR-s@?=LrHW~{lST)QRip)b&Gm~mUkmbHMWe%R4M!KfVe&O`b"
    "SM=^CjR6=<u?%P1imrQEjdI0R(BpRR3fZ|uiYIIX(^8EfZH!2Crn&S+TlaIUP3eX_W{N+QiXuSQZasicZ3#O!s<H$;X_>hrX1pd+"
    "rsM?zIF%QgxL?ydkqklz&q0k-Yk$bOhT0@qf{wxk8kg2aBk~9Fu3W5;0vVYynx>vA|NisUI84pl*RV?bszuIJG_-)jC-DN)$c3WO"
    "ioj2qK?dDanYtM*i*6_hirij0|IPKq{h9}?6?H%XsaK8i9_pn$miaN;+^9xYz7rXFlo-nd#gfcJxLH#u`Dtk1Z2z$3%g1>N?WVfR"
    "9&AWjJMA(c-<l4Ao;6u2sIu=zrVvQFRL2~{K{7Sz#gAWU<1{0Dw_WUx$)$W#5gb+%Nu(kp6NiqZ1K}Rf2hOOEZBnvpz@X5OOr`oH"
    "3}w0GmG*wdX{?*=?&j+1@>=5LiIhY|60Eah!+~@qO5hSe;4X!J75zn)WOZknh&)R%qX|#XF^Ji-O8m*9@twtB6yu?hGOFy5(nxyN"
    "66#)RG8?nT5mTI00a^BX&DNY3yzyj+XCt(qI-J*W-X1D135Ba7bDKHI+*A#mWn?F-y1`UDn1ZM>Mou9(wayqS;W~9Kqx0vrMxHO;"
    "jGo1-#V}ZWRv<)aDhfsdR*E47ask<ss!dl!Ga2BPYzG|$a%+97rN^r{VUVpnu580_HCs|K;UlYH6s<^XBo%;6aZnky+oeh=sv%wq"
    "ZEC<5Te^5+IN6F}iF2vSJ)~$uvcqDN2(}VHl$kQ8Rfr$*jBMY4jw*+v*5GA%t&!)3Ghu)`h!-E1O@dHlk3lsG%$g!CQm&B|D5PzY"
    "on|fIfl;b-&_(C^R!ff!N6xakTWpra(SY#jWzQTqsbxC^WA358ZnZ<HQMOn_ak!FD>+`9(KVDyMKOP@+aqrYbyiE2BBEu&G{Av-9"
    "L6E8JYm~iz0i~w~Br7B=MKxum?<BXRUu@!eRSsh{7cGonLB0u9MwFy=5?3POMcF!36QWRig>DC$gfllZk5ujK%RRZBGwqv?V|PE@"
    "OoS%cUkGw3jo`{|9ViyjoTTU;6y_?GtlS;SKrr#cW}PPq<?(E~>|sL>>&u^*!XGyCFoUK6yiykr<b;O6h-x+PTQw>m6bNxN*&Ay$"
    "1*b~I`l@BSk!(eKurc;gGpEXYbLVHn$|fF4?`X8QGRvTPmFk5;ENKxlhFVrdJ9rQJwUB8#D$Rw>=fL!+nY)2ek$RZ2fr}&}V7@F1"
    "F|u6+`wunKt=@Fm${c0E(}2$84T?Y@@nuK5x<ubTKXU=naEY?AZgR_rJlT2}2Q4wyNfrbQJxt&L9!Iq&dq+)%4x{5(^HxhwbVn8e"
    "s|HV{ILVMqmUZ;%fDf>|deeKHS+|IoqDwZ(Y+k1E*~OSIyETAzx!X`K->(<XP$oL#o$5^%PYzRj212m1-)m&qgGzlyTs0tFHCeMp"
    "(^IaHOMKa>cUS#SPb>$V!S|A+IF-~$Z4MO@4o;;fTZ5@tqvA@ev5nHq%J!_>6=FpNkm~F0Jh2<aua}8rjeI$x2oz7U<#B{6<t3uj"
    "gF`nXs7003Q;=O>Ze)vksAoWR+t8CXTCOB}Fu9YHsQ~koou<7am$`HYN#SvoN;XpDOF1BkqsS6r709}CgQFkszAaKHZEvpr@bN&j"
    "WLPsidB9Xl<_MECZb0JcYjlCY95mr%D}F4n6(ZR2OA_8_B){ipe_@-?sj=d11G!{Zf(wayQtC|fixb5TI$3~}a#J~Et>ofy`hY(;"
    "6|pQi^o7Ru<9b`<DLlLTS*^Ri$tE#AjNDTS<RC-au~<pyf{U>w*&HFYhSpNrswC^2v{(|5cfT(9a&vXadZf(LY%XN_@ziR^D!@j_"
    "F%=hlqAZlP8#?B!mIP=Glv+K`Rs$ENNFOCkN<0dBM&RvMAIx=~8gzClCG)Y~lmBI&UgHNqK1s+}MTJl*G3K(@GMkF$cv*Uv#g;lA"
    "NX31Fw@(i`%&UGs?%E-bLBhG?$=wKLXGc+^Nq2qFJqSm30Om|M$aWBhF}vbrPopD0M)kZMzWVO|{7}v$&JF3t;bo1q3DcN}502^w"
    "`9QWNGe*<MwrE?(z>XtF4U(^3IRCC~HV>ECPc3;_5NeaO0`?Rm6OgWvjIxpK!?>QQ1Bx8UJGr|cOYNAvTnMT{hJV&lE&Xo6<8bTE"
    "T~nORODeKdaoHG|%)lL|L!^KPoJ}Srq(mayf$~KbTpf+HQKX{JZ#H$;N`T*5Z%|sIlr>bEFo6Q9z-#;pm!wBJX<1qg6A2^?7*3aC"
    "wmsd?bKSRcQMP}0$Umo+64h4LDrjpp$xrrMQ|ks03xhG_RNphn{WdZ}XkQb`5-rX}{(0_fvVeDIEd0|-!B(iMKxnj7WT90ZWOG6z"
    "xmkxpcnUp{j2dM-jI9_Mk8m$^<MaNd#2{%@(3%gyGzAgh>YRWBt|S}&jkYDogpMOli6s1+p)!Sv7RJ)AwDUr2R#`C8oQ>h6l*)?F"
    "&rCF?AX^eV{_I<oX(VeB#iAwub{C7~8xx9utEIbz<Ga?Tl+n$0SLId|p-}7w{P+=Mc_LUTDWv>%{;;e-+cs%9Mz-w|-OpMRS3cj7"
    "$v69lnZUb)h?kmCGSjRlKIPsE%Hkn43r?1sXb5zz`57HdhU$VcCQ&7i7uwmEi_1IdyPqt+mnq7C;Ie|fGWC(g;Ze6NTZ;N9rN~WY"
    "Mio+O(o(rjaXTq+MnUo2^A?-BPoPTn<2Tv+CZI;u-6!hv{}cCa>y;cwvgQ*}iu2)ezHj#B+{_!qQL5e~i&ItXR_~{u-?9q8!a4w;"
    "*lSVUlt>Vjo*5DDZWiHTZn}+OO~<nxj1_=jOZB>+W+Bk4Z&m7~;4Z^~g#Ld2?b}c7%lPN%xP`5~PtqJnt1fs%aN2%?O{}Bh8PXp*"
    "310OOiS!!zF{pyjT2-!fng7P`U%!3+<@x#089Nd{$C9Q)0&hg(e9O6K?SFx?>xwR$p{m2>Hq0{aG653|r)`)1GZz719J_4KYfN>p"
    "p$w=^)z+^OtJ*4TZw^AYSa6~~@CYKGv8t=p_9$r_lvS?eaBO`0=cSJ(W>r<~Doh}b?HXoK-c0t`Md&(t-!KT>TY?*P-T9b>ya(PV"
    "<?S1GZe{JHff<Y%&`L$Eg%#{!SU~s?wVAthD&VvwJ9^(NEW;GqHd-RHnp@_sgaolfSfM2>@DVOYc&=8~Jc^HFHQB2+5()-6PCgGE"
    "uE4ul(KuDTV(Ihv{n*DpTMY`tf%OmNh7jOBHPtA}?}F-6v~QVVuPTmA!w3a~yKNuc5exgvowXN3FIx!DIeVv01SReGk#k<fENz7Y"
    "twPIb2o^`}*%uw`r6N$2I}x`rw*0-hYU9V|!E+1+zGNs=TaNc9QZs(7`kkRHP#u862C{{tCJ-D#$c+PfoS=`Sy?GgJZq=DS107e7"
    "gF2^e!yPgZ|EP@9n3294NXt1<m!eBG8`4K+bA1d|<KemQ8$8K)y_2B99!-S<dB6*F^y&rFieN_|=b6@=E`}t&y%y}RM4BL;+BZzS"
    "Dgu4Ue8;A*0hbjQjDd^eEh+C@@iSrj94wB@i%c>^Dbp?wN77kMWVv40TfbZbSh{^;!J9Z0>$bDTW45koe~vGyTV!9yRi%oF5ku_Q"
    "KpuzNVR2k?mi61uhp6SLBbCWIGQ?7C{lKqa-?bTGhh@MY-owZ{1RV+x#uy=o(zbSfy5dyzmqz}j3lPdbx-s%(rs5Z|G~HO774|~h"
    "Q&mEZj!)b~4StI0GO{>+RBVrMD&6}b7H0Q`nG*!(RM%U9>bimlBs4i?@F0`X_ehpVt_@TJ^V-3Uxhg^Za9PmXV8-6C@?W36y(CgT"
    "#BJLWUj?y)hOrRLh70dqRPnjBvkgsy<&Pe8xJ7oiPIqnG>ZRYd^O7Of)^RYF>|%|9L0Pn0#H3F{%v23l)y*qyzBsZ~>W0+YY+Qhl"
    "nXj0*QOEjXF(rRo7-8UG+YTC)MsBXRGRGtm!4gQTQ*;n3T_`xa1_X~|#Qm<t*I)$j333PVf;@F2fW@!}>3pirg>*ZeDvt0o*dF|$"
    "6U8mG0eWNz7+2`SiMiju{QT4Nm57s2-Zl}5z-LL{U?~CvQJ|*A>rbP*4!Zpen@Al8Abo6AqV(<poTY_#EWWG`{+!i~7jlr!eN@f_"
    "qF4P_hpbOUZ9Zy~a3k<>Z@4q>s#|&mCV06zj?p{F#LKt1DVRzyn+xg%sH?i?+%{nV&=}$WVkL^FUCA7@Ps9Lh0nW+0>$;7(#?S4`"
    "N!HMHt?2{tld0(wj6x*0Iximt&N@`urrj%*gx0AomZ_sp$ZD+GW4&(Xsn+OaDTKiMgYhAW&WkDl+(D13$tF~11)4pX_~3}U5yoLz"
    "lmKrAG!}o|%5h5jWCH%dO46T#-Zx0`0I!!W`UNOV5s1hFhowege%v;j1MvZmRh#IpoA~`#$p?Sm3x1v%{L#WjbOF*6PMIjbpuA)s"
    "e7cCVSdEbhu8y{W`BgW!w*(a+9GC0*sbKp&>+z>_S=9p%p>C|Knu#@ugi3w`t$55#SF<aybMnqi+SDK`Gf^wF+lHPh!+&b~+j<GE"
    "x)e|vLCyrv!-x@JH%TLq;8xzSN2C4jbnGa=C&C7qi$a6cg`D5D_u@dCsJhG0fzQyplA~0L2y!h2WamQKQ8gljM92(*o5ePC88b2F"
    "Zw%p=&!11?T~M8-Ckuha6G1w4$u$r{eexu825+g7t{5HGbd?Evco}~{$K&oY-u>fBdKD*yC7IP#r@}L(kx>9~44PxgCWy!|Kuz_c"
    "-s_gpGQh3{WVY7it435ib-Mi+S!bjG!8Q|gyBn0)AjQNtyE^0u_lnvHvMXV>f{|3E9D8<F+iJIr{BmMLm5LBG9pI)7$Z6yvk}Z=2"
    "DovT`AeOV{bfC*RUwn=kQwIes7eehd8!wd0!q}J2fq^ehr@>o{AQgrz;uvIXLKt4@Ri(q6eZN#8RPF)fmy!9Y?tJ{SeR*appZ_=h"
    "^J3Gm#&oLb^TIicSJmgPdG5_PH5U|ox&%)mGol${5t<xT$YYx|H*NmwmzNJCZbA+m?!YoC#sTS6qnW3!8KmO007yq^)j^Ooa6EW`"
    "WMBwCqWl*|em)(xt$QR+m%9o57A%cZGP#aG%KWD+X@wdN)rqdn;GA)v2Ju_Rjj79Fd#VRNw#H7-+YXYt0bDvGF14zPF_H_-7Yo*H"
    "NAV_c4tFg_#XWE?3${Wl#wzZXp_dH6K=rMCNtP)?-J!k!f}o;62&D#}=twf?E-qM6$hrfdilib%iF(Drx5F1tcPJo%&?XB=VyU&V"
    "l5IK)p4CX60~lg9lhTh}S%?x;oP1hLWjJ@trCl|mt;!P{b=yL8Ak8Z!*FL2L)RNBO7U+L?V8+y0w^gM^QN^4GT<Jp9V1DK;8>iC_"
    "rO<vrEnT+>Qox+5GvU&3CkAHJUaM{-YNx&lATFJLO&zoX+uSW1r|w>hK%Va5bls&Viy3lfS7O1pE4gamtsr$^)Mj2B9D!dSaDr0u"
    "6?FEBbCfxC7eaNi7BAcZ2<?&&zSX=F|3vgyLhGAotkb3>$pSt_H@mKE=e`P5rgySHtp4}_+``pjhl=Hcs>bH_IZBE}EY3$3RIY}^"
    "iNm#M-6fbft}q-e9xk?5dWvoNE;2yW>Q4JMOgu4FgR?DPw1Yf+)vn8Pg3J6|w@kdS)El<0?0FOwE;3ShoVIj=E+J-^QWs$YrdO9U"
    "fV1ICI<O-Ez^kop^0884ZP%@xT+Vpjj{qr!t&3WY<q8y&en+t|1F!?br4nF(VOQyn4MT!GWL|)-GrB~0N!@>KzkKJmKM-bnMRmFa"
    "j$q4*y<l{ptIezEZc9rEa?Q#k6sT;sb?tu<J8J<_r8!F_qh6ZpUw^wssJq{!Dd{_S()x5vj;a7yh6@(0Gcy(a6EkfpiCCck1Kf>X"
    "H(c7jVrYFm-PJpA_8=5uLnQ#Lvq+qQH8DuRs|+QF<8noUU=b=?O}&Q!1noL+zkL2@Xxf+Ge*b#EEnG}I&(2FYUfRCmi~WwkOk;^I"
    "bxqx=W^oDO!ARj9Mz=*3P>q<CRbdEN=1Q`cmDg)5FA4CB(Hfo-tQ|HMvhar2;v8#e8;4{F?SN6I0sOKhroc*Ig-<iDnfQJzf4{N%"
    "{PVmrSWBnAEiz<o>O2DI&ob+iFbpng%AK&T49|p34qZtMpqR$Ufu~sjmu9|PJ2)g1LQm2b2*vMr8d0a$eKcT%wkTb57B1^z0NJR7"
    "wh;>8Oxl32S3ut9ub&_=FYQ!L#tjIeqajvpQl%ke7FX0Y$*c-K!ke%Lvlp0dm20<IEf9%`gIHfK;~#ByE`(8@{bs``r`^T2G|V<@"
    "8QpO1Fl4JLhrK1Y<A6<Z>%t%_&dm-|)@{*L>-z@3-wJ(*y&qC3&#Wo>Ow?Ms?B`3@Wi3H*%aj2)mrJR^cA@gXa$R&#CHIsf1fhc="
    "4)57|)=YWHe?YHPU|l-JY*O;lafu<47M42vx=6TC*Z#Zr(wNdlHvBY&sS1n_89X_}0<%j?$Y`Y$ZSncsbPpAW3P(Yl^kK-h3<22}"
    "+TgS<=TtG#mAZ=8*6u!KZ`4_=>>;9&q(nAo(eK`;pjL8gk%n!aOC_rXtRk&3r^+%oLnNSYo8m1uxTbM(=dZjFJGt}hU8<hk`2*jQ"
    "Ke@N*%j2AuyJ~f}ZWxLD0?6x>x}76to19WihbpGj11+n{8sJ(@#~o^LaD2nk*`W>zaVy0LnD3DiD6EmvNHn^O5i7u=khXDglDW3h"
    "wI^OPxNzv=eZOVthBC^%hw@S)<zW_Ylv)|`=T;c@yEMOcixm!PnYQIg<u;}w{%9KckO*6dpVnn)aEu}M^-;4g6UrClk_Gdbs1@Oi"
    "pc2)}>WY%tRz+My_gzUO)u?<&N`X>YIj#!4Yw%*Pjog$i$eRCHC|%gPF%Gu}T(gu)NV<!eh=96o<N(G|7d@m<IF!Q1yB4pXpaGOf"
    "fvuCLNQ{Xu0rg9MWN4c*$LLg1>!39tLCL@3EV^UP@ahWa4XdYmDtBHwSA|txQU^n0i{O2daNGj?3tXl)6Fi+KV^0bL66OMef)6WE"
    "R=yb|Nb$bS7loBO$MWk^E6-aI+Te19#h1sF=E0Dha4p4G!yIO^r*wk>_J*Y^iQH;c><ZiN5=6OW^u4pHK8!?MrI*xL7OrnTfBTtq"
    "e84Bqw#`&&e3^A?7IkbsvP8NXfZ5!%`z*e4=jC&A?|axmY+-?Dcb1&sB<R{>JGNPMngFP)b)?l`z;%*P76hZ?t9JD4Z{fu=IhH$r"
    "-A!GVhuD23(DEpY_cnAzvgJ8TjktF$&gHGLjs|O<URow_#iqTjD5bKY>piJ0vm2axO&GP&T^`@wv3R20a_4Wn5OKM;y(?-icMhj#"
    "vMzTfZKwJ!_x`XOdx<-*T1?iK`>N5#8W-@$S{5UrYh_&=_IyMT*x?<>A{(rcqR!roDL2eLE56)$iD2h3Yw@ba%=6A~TB$dk6Kw5%"
    "4!LmE40`gYwku7kA?&rSsw_zl)tae$fP=ZT>w`8g3Zn0{R9>sj+<RP~<!A0}=(-Ng^LFRfU48QRki4Pa85mR(#)nkrI!MNYufa+w"
    "577QvZmj}paT4o|YrSFgM3CkIpLnWFb8mAuBx>$#_Ef9pc}o;FqLZ&u9dNT8_iqO&w~k;s|8A-h;W!r_Y3TIHACmn+B?dZ}yJ708"
    "Xw98J?_9m+G3HKXY#w9r$^qJa4W0|zJjUva!p+_7y_UMUx4BErn>$-P6Tf+kwWn)}_qKK>hjV9hS9Eb6Ve!i&h}bKooCnx?6q9|W"
    "o$~-&ugWv;Xy;N*=Yd8aVe3U-=ibJig?3&Fd5X%ZYm9qGD^+FC|4z~#7&&F9-bK@_4o2F&ZmWJX)2=YAw9NZ>%g|{>^&0(<f7>z5"
    "ox=*nbRSxarlv7{>E`Gwvs!T3tQeQ{yN1hIb-b{a8+Kkx@7#IxZfo$o)Q(NFrREr;Eo<$ny8_G4Bw4tcVv;hGO1>mh<7=3;NMt&P"
    "9b4$hzGL_i+nU!@d7k(DtF~g}(q&rRpj6#N&(qXkLvhwLwKQAV2AgJ;5VcfnQk%N5G3+QeO}>)nx%UUY*6De^_}0seo~71n@h#Sz"
    "C7P;>bz_vpYedzzFD=#G>hO{xEk?p8&aqa_d)BU;GNu?Lyt8^`I8ErGlsr_6Eww(&qEMNbuKy<8F|1NOvNen)fyi;9H~f~#v*Sjm"
    "*L6%?tViM7s6#RUtNJ{9vBoiyq4ci8<;^IMw$^b0W@H;@Yj2wT`Fu>XV;XF5h2SD(o3?A#t%tBfN@1@sXIJ@-E6v+5Ran*MR*761"
    "e(razT^Z9uhi`fBO5&YcgtMz2yX)$2YPvfgM^*=bVssgBZ!7&q_+D2poSQW7nyAmqNtk-|DNt3(EV0-_UUqqBB_f|^lllrX9dL9X"
    "W2mF3zn$+nSrwGsF!@T|=gvNHA@lPPd$06<9%%6q9Q{H8=ppt_q<|i2??J|1i32^-<bx>Qg<Q}>?49ZcJ<i}mhxG2oerqaS`sdQt"
    ">Wl07u8Xq0>z=^WU6=*-?dp5Gr+Ukz9n>~%^{~d8&RSol&n>jP)Zpn7QvCMw?_YoV`ujd*;}Ti}IY(iGK65_`6xyh@m{Ny&r|2%f"
    "<9SPU(z?r0%uIfi)YQA+(#ZEUug$lg+i&+P#eMBt50JVbx2-S#3Cw&|KsTzJQ9^m8uogf+DW{o@QDHBjPvz`c*8-y21W0WRs8l@g"
    ")_aZfB?0>Sd*7dbp2xw(t8+9P4iQ(~O#|#_<9$v(XJJ1;)|4)n^(#(Y`+^gxBZ%tvcNompwJTD$fx1)E<C-S`Qr8P3B(JG?qncS{"
    "Uu~6OfKR!Xv?LO*8lj*|21lFTaaq6i^}oUB|9ZNIb*jYlQgI%;o6}5KowH4sGd3tXlvd`F+ETMNFNp+CuM4a(%q7(^_2FeP#`2EM"
    "Lr3BSb0y=|JImK>Mo+Bm<|}??=YUmW3fwG#{S<qsx=dSIH9?KdO!HT6I)A@fc13<8NS{kRvSB!3+X6oZ6thhDK`oKtGA(*L{NP(!"
    "w;PI}UeYXI9q`>UbY*W_YRM98W#W8vEUuJU<E*~TNbc^lTBm@Yw{t_a>O?TyTE|VSs4?xErml$ONS9=e;qaZ9?R0~`Hxk~J+CwJ#"
    "L0N0cbwI?iIjfgwzzDTP-5R_!_d`qMwSVQ++|Dq6A52}nMW=>DHLIEV1`-dWe!)c5A)qXgHR<j-A!_~h6*Jmec%?1HREH{wv{H@T"
    "M`K_q!JFYmkzYGqb38gnM4O8pedsQfg$n`H{S}=G)zp9fdJxjnGu*LqA|{pCc^1AUnFS+l7LO5CwlPN%)JsJC<$~(R=1}7!XBgxX"
    "uGsm`>n}GFpwiO68WB>`Arw_D{d!H)>5kTF(N?K<cipaNx_W4niBj$gwVQCII_ih1m$EOGE+do-{-eAk#n4t(U@3GacMLd7V`U5#"
    "GQ?W=FkQ!zLY&H7`xOH(;Yd^Tas&<EsSbNHDo}R|(Y4#vk)wJ6cOANAl@;JTT{q8+whk6Pgv;hDaY51mueKhC6p0$~l0Xgx)8%3l"
    ")h#!<D&^ZqG);+slzS`$J!#NcUDJ0`h`Tob*S84Z-D;Q~v#xj&;xa=hp-tUr%o|rpHp1$x`d`?^Wbr$aAe(^*!O-2dbA`xGmmrjV"
    "+GKTKXU3|#=OyZHZjtClsgl<WM`3%hx{N#{p|*(bhOyo@c1B@0ES2y-)PTA250-Ej$h)k8DtVry0v74`_2UY+3ApM?iAA%CQ}foB"
    "U2F(c-7k@_Q-R{IL9~f0<gmR3T@g|T>_6;2GV#ZB20M!?H@}Q-tSo=q&Xo~#(g4V6X-j}qb9Hc#+6R&>f`|TZ1pt3s@2;$coI|Tp"
    "=mJ7X$-%vC?0geoffAEsk&4^AJwe8I6D7iw3<j-fy7bgdTU%Z0i9<#O8H05g+m+bxgo}P%|8;VMKQCaa84`2HEw!8_8S98R4(IBl"
    "mPXKy63@bA3+sSyODe@FE~oNxqu~HwxAn%JrB?xxc7PL%YrSV8fmtRy5UraezUfIkK1jDqS3aFoCAasjhlHOkcV<q1|HP^6-wglv"
    "q#x>8(YUFAn3RH(x<xg2)E7%4n-!g_+OfppBZ(oXytz&TN>Zc9^UpeiuurPEW@f%5szdhPTQUJ^cEswKWFrP@r5;R9&PI|uJOIS3"
    "eQD=?AZFF;Ms5wAAst8vWf^sOl(eEJj|0GsG=Jj+dt0K_lCX4?P*V-L?Re-)%yDv6`Mb4)H2v6k{`!;uo69ewXCuI_%2g}tZw;kQ"
    "VLOt7R4y4JzCqIFfQdsQJ*mx{YkZx<y`GcBm-QcOD1LwX^|#-@J-0&9#<f+mDspn$Mt$;Hb3t-Au_!gQodG;Xn~Fv)6p68`c7hXF"
    "y!7z$_;2mguNRMJE%^qx243(TQ|+;aM8|MWLu?@udB|D~k}Ovzj4jE&pdR;XU-gvg+~5D-|Mh?U-~Z45`r9v4>nWtwOd;MkQnG~J"
    "Nz#=scU_u9x__7!(;&fsKHD&W(P)aV>I-h3dd9hv4&BeaD5Pivd2{OcVUoJe6?{$vQvLK?m0%iB6MmpFKVFk8OHlCOVBw~xCkwzl"
    "4}n^;M7RJ@Q*~KMqZ_hS%RaLw_>Rb4jl_Ei@C0Lgz!^KF)|qF0;vnwt-v{>Z?U(-PAHRQwE1v8FL2wtd(sgP>s8iRW4ap(uT3F&V"
    "x~Sk*Vw4zSrxH{3@|roR83x{R)5ewk3LaLM=e5T;I^}`W30z6tm84>^4Zh%QD4uVsoi(Js5VlCVH?nZjO<U(Yr=`Z+!l}VayQr0n"
    "Q(rBU)VQWedk<bcm4d~%QV;~FYD%U%eY=G-L!<rtv#yk#H(p)|aL0d1{d<%AtdKL%#E-BwUUqg|mZj8s9uY4)I_j(>*$5nDy=Ue{"
    "1w^P=*EC@&TWA@e4C~a3Cm%LI&j%;ncu_(q#}>*^Q6C=ZpX9-B+xb7Aep3!9VDaAjfa(^>yAqHLtf))DLVAMO<7?cSfHT5F4Kp_!"
    "0|emI^yu8m50S_7y}+gZ;qK^2K}tND<ABd38n#*2B7mLDG@5k0T7V-MmCJ9ajl*Tb`NxoRUp7{vgv-L51>#IDAP!7PP1pgb2Z)8B"
    "R**|g;T)fH+|o#rA`avyXV0ho<)+JNPv<&8RT5;Hj!ZkcQ(Fdg&?BlrT#b}4@qaRK6kHl1O9KMBy@BUXU3_oYxYLBcHgcEQ{>P_p"
    "PdiXg5wZFXz%9wEZ9!8*14xo~)(E#|!jRRCVssE{;Wv|?R==o=LXzkVw+*~p`iHo|vAS-D=uW;}dv56`7HH2j!PY|{%fl{)omK*c"
    "Qi*Uth%}xO_caT58KS4E`){9qd1+|lB<Ku`k_xf<^5F{w2n+}vYSQlDlB+<i)*@X?7(v=QQkqa(_c`7&ai_)f%Eny=>gBS)=dP`}"
    "_PW`<y3P|chOtIXGHQ!>oNh`SYAN`*(wJ-TNbP4aevB2A&zlzW(-q8jY~5+-t{c1082-2)a7~q?9(rt&(Cl0KVxWc%S}?W5kaX1w"
    "3~j-IR-j<0|BX8Gk-F@H4AyeP)F<5uQeoJu`64Bj1j}YXf~uj_;eIhvt>{9f*=m&$@X%^N_0ZQIvKrZk30+sS;Ex%**MwcScGnqu"
    "#5(+8>g)RXJFq|Pu_a9=CIPQWFw!a!5Ri+@hbnjRj>W(enIu1@g9|SP>8QI$)`gX^KV<8nA9mO2`uh3zFE2D;s5OJfbGntpcUC8A"
    "8$y8Ig#su9&3biqDzijDG{Y##{F;qAJh-RceYcF<Yt(Lu1$jGhPqD#fqAwkIuA5A$+p2aDFpxei{+k-V*geS`#x|rRy7~#H`C;a}"
    "q|Uh!m>YwztS1&hy_llWI{47(Rt4E{6_tkN00jX?2PvcMH3?sQ*i7;KTYme!19k2@E3a+bX;NMrxyurM*0}s$9Pq0A0S1|7O42t~"
    "cTCT0K#e?HJV_F4K*z!|gDiXO1G%)+#kZ+Bh^f!|1Lvlm{qnTO5(G*`RHURX^=)G$mU$?S@kKv+JE@;vl>{0*0b++q$ei}%K=&Up"
    "b*D+XYU^He^}LO~ejT4*-DsT5!&G}77A%7T9pP)Db*=Kfy&0#%!=zqWTYY>Q>%RjxVc12zU)&qE{`vXj_@B4SdiJV1=CmmV>yyK8"
    "TF@2j#@9$`JhuqaT9VQCg4~CiP@41Nn||y(pNKNl86^DbmrdG|I>dstUlq55qvxVeDbgba#7{td+&QErn6GX8tIt2lHnzvfZ0dTt"
    "fp4TpBpW+fmU<W#Oc|#X<Rs&%o=30?lR=SvNE2qP^Y_2jXN@EnY>a&xZM@H^%C)(V<`TT@^s}*~SkHs`0hu;w<x2-K>tKht^OlJ_"
    "E#g-;?y`7a7a^VXqEh1;uhweAHYw~owP;cs5Xs@$SftXbHqn#+&7t+FF2pQezCD<yo+fXby6eE5*?PbLzBF`mb6H;1;rgu%tM)?V"
    "$*D6Ub#RW}wFZWFv*=>6dIAx>+rYf~?p$!}o5f;x9XRYfV9?IGhK0R{o$62LrJFkX9s^F2B$}euKvQ)wIzFvdg74T=y8-RmCS&ci"
    "AF}n3;d?T6&oTV+StkI@)awqJRhsf6h3=byCFEVwuKYhVVJ{u1#;iJt>d8xROqX0C$+zjcq{i0=joo(?&#iqQMiY`Tg9Mbbx-z;v"
    "hk8&!dX^!yM|JE{4+j^r8a?WS<&YGgaped&zG~~T;U5_~z>cfBYN;`+TeYXga5g^yR={l#t2aF{a&0$fJhZH^R3m@ulX=g~U5D<("
    "&K=j@Gq!r2HjESeE45Vhm()>a06H@KYIa<*^Sx{x4$d-{kV^6^BvlnK$S)nt-?4Sq;X5~W&oMkm#Mubism4P@ICW6jc}|r{s38K#"
    "r%D1c&7wo=5Lw-GGp<hZ)^ISO%BuDQmhL-#uT1?<j-LPf-~RFG+jH^FS1q@$F<Da2Or+UubhIN~>}a=&l1RATchA36&y1;lZooT6"
    "ID04cq^Ad;9!9GBr0)Ny*T`zsIOqBXUz=K^viE4xmkfolX{=7}u@i|weyASdiTC)E!^oe0X}^BjCv#j4)NH_=ERiX#41LBC2K*V!"
    "3uwn-44IBRIE}id6y7KX@4&-guvsomyqwOa7F#SM`|9h;4D@zIomHCz=+rxT5UNN7W=X($!#k31)2_%T$N2Q*SLdA!XIF1{vqw9s"
    "O(K6FvM}6QvAF;}V6rR#aSUxwb?p{v?v6%B;dzwjr?2D7r(Zt(`g$j_tJtpuh<zlUi?}30ZMCL2>(y9{-vFRzp`*p{z-Ke-Z_NeI"
    "$@b~#NAdpGzmp=YaeN<aby(uG{@Duo57W|)34ArkbUJr{xB8xaQn&96MX1$<zkU1Hx9^$ePd(=BtyEORFfW+66!yKEH}G8s5(RKp"
    "yK!}wX-P>;Vs?8vfkt2I(P8H4t^Vv|&fd!RW!F*yH9*kiL+}z#^9Hu1?m<Ph9Xi}7zE)OvG*JzSMge&>zVydi{n^KyztsqxNH8r9"
    "Hw;`eSw?*~(t9a{Kj2Kr2DfO3)Pt2AE_7ca{$bP-pWf<EKIZJLf|=TOg7T`(tXf1e&#JHJpn2xO`=Tb}x_)V;oxBNd+Q15-mN85I"
    "@m7EKF=ua;RJc^V>&xu{#~9J8;+0q-QGBaHH;7v?d{y625ja0lQD+L;+<$(nKl_-ox02S%w2pkfZ6WHG$$AZ~r9nhfd&g|--uSk9"
    "9ETmJ&83uRT~4F0Y<|4epMA{PTb13Ctrn+_@Uyb`dp>CSyp!Z)7t6q<q8_c02((O_b1Ow16{>abA8++%A9MCrV$RD3CqbXNcTb`A"
    "qZ&oB-1u_ft1}+nNfBdPU3CD<t9GmEKz06jt3Ugg^S2r}D|6o6Y)hS9t#5FHq@roH`dlQVn9H^*8`*_q8gt`U*CZTb?&+=m<YUg>"
    "YT&Ls(U?wRC-pGRbH}AF18T%fR@zG|6!uMcRu6^=zGxt&KGpE#$6Ni`$DF^FM8Z-HZEM>TKoG++A?&H*BtKP69J{FvjMZY=AS{Q="
    "uprcs#<r&@`ez?={#H66@{+oRLtB%Yx@(hS$skp^J9n!_@N0TzCJ&=Kti+=Qf>PD!lMnvc$DF;@G)7J6eRVOY5SKV3S^gPJF<E`c"
    "vdJnI)6JOJ!6Yg*De6wpb(z=wc&k7An6tN94y?g*q_8^Evaar<GEdDOAt?mFVS*Y$7p>)P)kO>lV2ipWm~MW&)t`OL*;|3v!sfFY"
    "4+K+zaT#cp+&XC?ktc?2{5T#pz(+qaCAJMHSX-rGKi=xkKIZ(ba80$306?=+0lg&9zLV*?Oipq)YQDCu+64918bF*p!PMvm4X}DW"
    "z15$5%+p&P+~WdZ8|V^<8GITxVLArM6jbtvvm>v%N?vLeheuD6g<ons$LI|H%5JXs>gkGx|KIPQ)J$0NsO{6wYyM4DT3^2&>Pk<<"
    "Z7dh6Z@sEVt$G-Ht3~Mxu);K59y6YKUv2fV0BYK`(&2k3gyEduw>jEx-+uq{jP=$34I}~P)EyJjV~C)@z}#82q+AC~mU>onVKi0e"
    "XJCHZ#NFxE3;DTikSYJ|`8>$>p~{!4&G}p;vTG#=n_0<jX}}wV-bx<Ns0E&Kux`Ukza17*FU);!GJIMI@lup~|IvNR`q?;Fz(k3&"
    "u1!o9TaJey1Sr1%%*I-yLauxaa4*Jw5{|RoiSWIpv^@Wa>A!5mzpVfKwEpXv^7#%j2VAKvc>_|LdeSTdpQr*9MQvPCf^L+>5+oHd"
    "@IbRs$n9i@bJOFW?N=#A{OA{Q_vt;ecQ&CukVSJzgDE?N6-JyoCEea@qku3T+mZ}Gm^&;-#u(~RQ%WZj*B8cl-Pk>+@XXZNq;<6+"
    "JT{2b+(#OpL<op!HZEur7^~{RX4g#CS+_wpP{Wdn8f@3S&W(Nk^*?_9b?DmQsn)>#C-1u5vq|hK{O(Em?7(dv77akQ>Z)RIJtbWm"
    "fER=sMVZr4qz$WrsmIp*M?dzilX>0b*`(T7N!AklHdDB&4gXzUIDkf-jb^MCM_0RI!9`oQuZFiuutt!fIX8MV+kWhPUYI<aO6&2("
    "S^6BA{IAiCx{1XM51WqCv;yngYCIXVrzA}d0ANmYGzg-7*WO)c@xt2K1gZm_1s6+p$Aki8R)<b6Al4aG>AEgm=h{%T;M6u^8|TRz"
    "L|cf-`2<cPz;SJJ&3~->Pu^>D=b6#<V59EBM6zAeIa46_4JZ`BC)bjk+U0sYa2|~;m+o=FWlAUX=JlqnSCa;-b!y%NUB!>h)-^#u"
    "J^!U%*$F2ANvb-@_^O-WDlA@A#LiWdXMEGreZ%Nnzbz@sjsN~Gu_$@De?4I0u9`iYz~n|9z(d_*O4;wGMpk^$QE8Z)wQX*Ol4K7N"
    "Ch?o4%Y|*hMWN`{eaPlLz3;lkyHDtsH4cTlPxB!Yd1CHt0#}6j1I4zk#w}B}AptJCp~KMdWP&=<;*s7HV@-BFE;Zw`Re)`l{-&)v"
    "Puz*6vk6mo$gb9AYUF{No2XJ9$TIof2HmP%Ivr|ox&hJ#eA}7*0-Yt@zrXPI-`md*&3NYq&nC?jwZ$OW;X^SIo$@S&yl#_=4LnoT"
    "l|8DjFi@p7Wp;efN2BhX#`<@x-F4c|Y@O%2P_{@>7-=0_wAh<YJ6f@po>tQR%C?8eY6U#i(OO4zF=lI39(Q5w^n%O-rtQ?+*`%rc"
    "*x1^_ZB`c#YwtwDKJ(C(ILMFfRV_Q!rj-on0BX!2amDA-><Dk#y6=>oTDo&+JZVDo-Od9i?aAbQ+1{nS$4uUnwR4Zl(rIDTiqTa~"
    "&&N3<k&yr*lhTUqWif^`?&|q$0A};*9-sL=z}cC-?+R!qYA1J}zYB}!Jg@7ugH_>;rY_VRQnCd8j^T3jq&AWQDmbIxia<Uj>!akK"
    "Oo{KAyXWj(7(35%wnV?Gl?111DhP_&LC;0)y;IZuTeTr!(2}@A>I?255XP{UY|n@C)2~krfPU)j>!$}e--X4q$#c-wVN3T?6a~3U"
    "U{&G{SzMh@N$Qu8rB*W;OMa?G^TyRBp#?tuJ#+V*ybEJzlQ&ahB|<r>QDYc&QU+L+hMSq(r|GQKE;BwRos+sS3cN^~C$q)S&dmLc"
    "lYe<?iu0tR^!u+Q+Rs1#=OZ?p-+O`khSm41-*cwlvwg866K&snF`w$JqmtelTphcXfjj%*magOxgX-KQOOKlqyL6j$*6!+=^{2~3"
    "Pvd*{i9R=Y&!IiHbzk`LZ0+aIUmrV^KMda2N6xK1W-wnU_T$F$#O7m$^u*vJ+~LIBV<r(J^JwYwBf9;g{r0%oyk`6yD8vyY1n6z-"
    "x?l!ejm-vU#-3^bJ92I6eNGI8c&QYYX}7A%E7}Gxf57r1=J%T2`@)CkYs$YqQH96N?}^RFc<YJ5N6hAlxwA>cSmU#*DVDJU;pSx|"
    "Oy(0m-|B}d$-G!fS<IZyriQNKcE57VCYu`upR`#XHiJ(FA2WSV)*dl;PqrQtW*@feac=N26ZeQ6kK@++Pv7=0KYd-}^RM$ps#5D!"
    "GgDQ`ahLvN+Q95(oM3oRi*9u;DL7$oxZ6(2mQZ3OhE`vO{fO1GL6v%B9dlaay1FiIpF(GhYqN6|GFPq=)#xFs0JV=OQK{BOiPE}!"
    "YTW&{$yX!GdI?=6C2pv|VmNCsq}~LUF>bAN-IqVKS@-J6Y$A#c$61`@Y34@^o^zW*Vr2-mr{XFO!CD-<@0{u~Dteu{N0S-zZSAN^"
    "(<v=nL)|r24)2+KlhEFKPH&Uh<4Sb3x}LIDQ62A!B;~z4UtU_QQFo<V4@88$&73jE<{4vGO&liw0m~1a;oBrO2vm8j5CN;Ps$yD1"
    "jbKCTO?|`5p4yXwx4H_>QX`JqQ#Y;XI`(a^{c-Q{Y7ATfOb52Hm4#$>o}GZoi||<^F2GOg+5#&o=w4nYja@Rq!AsNG&G&7d?;T1J"
    "IjoqSir;kWW;-L5*ODrbYveKJk_I-0CB}-=j!dvxQTk*310VVNkh*wcuCserU+a)sw;Op|1r7CowqdTks@0}Iu9Fdv(wZ*o*R88v"
    "@0&ZDL|swOrY*0d_qfXLtl7kr&18xnTfN_<_$uwh;R7*hMBuXylk%MDJd3GK?B}na?w`G$44v13SSyLzHLV}kuhHCWJ^-2U$37+="
    "u~!0BW!?X+F|Iz#C`_=IplUZatlTqOJ=r)fpR3!F3#4eQeqD<k>+B?i`PlI79>)qJZ8EXs)(d#QOZ%V_1zI5@oLRxbPZGIiVm|Fp"
    "kJt>nuy}ri$$Ur!)9AKcWWI<CzI&dgBIk0{uKNYRV0H-8s^vFpRNcyBF4ua`+&$;)!q_=8t9Wj3DKJ98Mi*>v(+AtIoptG|^kH^l"
    "^hiz#!Y19WFcw~w6s*t9{r>Hz&s)vinXb=Y{`+C{?3UsCV#Qll?>eJ5Y@SVQi-k|I(>6uhTz7Yt2`<U%1Zg+E9bnhJE<6NA9{g`X"
    "7Q5Hv7?caEN6V5&Zm3*XJg*4fd|j>9kT8w(YYmBwv`x4yN)W9!f@(C5oZG7#Ry_k4`do!nYkbe#UFY!J*xBSIkibeH4;+msN)ijv"
    "k7jmsR^3@<c4_t~HD7Wp2r)1GcFf?tCn29loFBaKM-#iJ&HwvP;SIaz+hLhpC$-H^LWnR`lAQ{B;Hz@eW@7>X=HRy^zz9Co0c=7l"
    "Cd8F5fXfY|_ngifCeKl5=NpzO7&PiGqD$OGnjU7Dc>K$5XL1n)XoBR-JHbddyj@&tuJfamFM!xjzkU1ZTl?~l_3eSz32qra&zib5"
    "SO}&=f}xlJhEBlQo~|+OR(HRO1r*QP+z5^l_rTC1rD?Kj_@LE$&g(6k_uXIl{`8+fTi>s|ALn$BIpV%;`o4Mew%z+q?=7q6;TW(N"
    "#f|NpWSy=qOT=Z<YS~s|J#i0+<!YV9n@4J%_i1XCqZXRGT(|oqp7XG9e8cWTruN+E1LpPI<T*f6*C%5<bH`_vB*pm@V++1yQs`E-"
    "_X^;N;FiloX<gF=Oi9TbU$57VKC+16(&R&?@<D|Pm)6dy%gWgqi7<}YS5CPwlaB0>ZL|l~>}qD#z))$_tsQ}qjmfww!*DU0U)wM1"
    "bOYk0qxan>^0w)-3C)?oYhyz{TOiUnBh|{{)l{Vrh>CRqywsuMR(&pvTjVB&Xyg=qYah1zdSZiWl;_UcDqJC@IG_&AwplD0j~PvU"
    "g*l|j1BQ!Ecjx%rsF}_oeAw#Q1gnvhFab|n4NPceQv+TWYA7Q+UwZYvW!I&c3Im9IG2d?1tY&(Dj_|($&UEGTKi5zHwc7v2>~H`5"
    "^V$!X-<y`t%Wlmy7Orh|HtYh9L8Qq+n7D=&aLwftp^9L%4lM>ddr-_ul8(E8OgGKm(`|1WJ>NAdYG&=r%xY)p2k;Od9X2_2-!P_3"
    "YjJ1ZBBrpQt`N68!nRSOW9xkX@b_QWzkd6!W%Ya>ee|}y`{drVeBWSv)9gJb_omVNBI2iBbo<l#c|KxBPtBc8WAQ{?AJjyv;+#=Z"
    "|BftU4-E}9Vs#R>szI$2_@cFRLveW@EQ@!iH*MW_?oKV;d%_M);**xv516!bljp}?&gVg@lFGC67y9(mr8T^p5h|*El@zA4sT*~I"
    "Tq<s`%xjs$^%(rS_U=1*=hp5!f&caC+dm(Ai|E|o`Q1IqV8m9pN`*)pOrtjgfZn_+-~-5=98yUZ+FsdyxuX;n6jVnKe!gSvo>O;j"
    ">ulnjsl)||W7*?S(5T}cfG1i;ZpApmYQ~kyC(ppY+<E)G%V;Xb+3oxs=()H1Z~r7Re|`YCxv+RPb#X9qS*oOf#ah}>We|%n>&{yh"
    "WYjJ+gA0NI;dw9~zoBlaQTl`LntL^O$&Kk|@M>ti^;eJfQ1?&j;^$%Sac7<Fx2V=zapl%@m%I-((VF8uV|Vtt@0z9<x_;Sm0Iut("
    "R(*?d>7ehd_I*Hp1G^bjqJ{Nnec)ZfWwJUW4r5ZC%U@m<d~NRhd=e;{lWIWH+K^#ZO7=QKAm7Cdsp>5Fxt%H!`fONa4KsBaAh-Os"
    "Z`yh_XO1r_pk4<8%9BsYJv8t>Yh!eY`{xO0a$YK&Y3Oz?t1+oaBf$Q`eACjyChSQ9`9c2n%H}ys)P+0)BMaGjbyDtmcH;?F+Db2t"
    "7{&XH!~EX)*wIk+!7f#e@7((a?;0;J&E0nr|IhmJ`K3tt)4I0Ly4@J1N|w(MLxvj>m&(Kv&yd9e5mrCVXnRn%z_bbKO#+q48D@2l"
    "cTHYgb(YX_H_KqP<>(kxyNc5dxS^5<i9-NgGH&Q`!4=JDtH!e3YWV_XUfO$I%YkPt*Nt+Ii(3*|tw2J9I^ar<VzonwQ;jw@Ym{(W"
    ";==AE44Cr%fSz9k(}K4~_etZ%56BPM*#aJ$hJ>yTnowJ{Q3qACP_ltB^_ZO+cBlNj_4eG5_K3~=k>YE1km35$ZsFvIKnFX4<q;oa"
    "#c#KzG@Es6yh*fzY`|zoAFF8@GxJ0c?6s-9D+4gg$~C?8zdiY(_Mdi7o6qV1$dVdsq1V3Eu{Ev)N}2j4W)xHd>`X7p9<NP7gDWi1"
    "5DQ+KNSyvq4Kl6ClVGVvtI6>5Sk$83`mIjZ%v5fLGz$?a8<-nzn8IcHkQRcS;iUo3$q$2r)kxg14xLEyv>6)yroASnhIP}8EzE3U"
    "Fw+E6S9f9RYtu!uzqP-8@3L#XL^ReUHoi3EIsKvP3^P%S_+(?3z-y?9HLhc9>%DGBuE}~)qjk0ERvYm5jPe!16Bu*u?nNQ`<cBGZ"
    "F+)syN0%Z5KxV>(?v*)9kTlIKL@yV7A#{_k+IY`sC3KAFO-j+e^g%oMVFr%`r#hhQRCc#Yh^!1LMJ`n*S`)jL7n8q32j+kq-!&T4"
    "d)vp3&%GEu`5_T=?kcU4vZf@1NWqc<#?hko{Wkv*V~SDzi1CTC%KJta)1y{+dz~14`5{5_(6Fu{$Te9lq2!#5sv8@CF_f}uBQETu"
    "`5+yd`L0piO**8(`}|_`<cBs%Lsb%cX_F59X7a4=C6I!9*}+N3jI7CvKol8**wTAOyY6;ckdfK#r6=Uc57iHM0BS0Z&RT66OK8bT"
    "%}cHH5cSEK45>EoE$BR=ziYG-xkw38M|v@O@<Txl61iV-klKT-1UdCB*`;UzGC+LSYLh=MSZrHP>OF25orJL#F){Yb>OKA8&{Y+u"
    "rqPMmR7ccyB~i9OR;njDkQ<vy4xLo-dsc&*_l)xAnL%&VYw;x_o&2yE)-XswE#aCP`Xx-Uj*RjWFvHsrDhS7GQLFBCcKfc;iVtdF"
    "tSu)UV_$ygi0uXNGHfY31DPNb3Q^vQ$pqH5-DDLOkb&E%k|DPDjBfQuacW_fUsmtw562O5;f1afE5JQ=)vjL7)(7>HWp(q-D}kbi"
    "A{Oc9BSr^n-MDJpsnO>jro4Ou!MNml$!=^Cj_7sPDZWim(++4iQEi4J*(Rj)ZgAK{HZSph=H$ib$q(Boi`R$pN@?58y7-S%Iqpgl"
    "H8ai?;IWlF&zNvG8{U{xcNh&2LkLij7}`sJv6COFPdzMDJ({Bj=n!%MM0p3VFdO-_B0#-W#S5mGn&0<~;&K8kkth~Uvdqg5K^X$("
    "tl`!h^jJqUR<hVZO>1%9+*=T|ldgGIU*UYyW%^S-9U#X7tRa=X<kOQMs>LO6V5|59hUE#b8}Oywuhn9TrBun6#0G$Fy6kIue$S|{"
    "!!rM7gX>;8A)ovZoWInuo+t%!C4EJx{kEQep0G%1+d^6salh`S!n9%E{Zg<mVOF97;bkG6{t!40Dz^~TRwT>9m%yjg8`-g}hpNM*"
    "G8_Rm652K<TmPQX&L0u*;#vJA_MZIEbb^e8G6?}~bimeBwrxhT6hrdV5`+OM6?J!?(~e|r867{265=3OArbgqR`2N#yZYV7)F74H"
    "FMNnJ<E(UxR}2fvrH)q8)pP0(9s!@my=QcJqqg%&s!J#B7+-!k)ciob3gI|)&E_T{mLcx)nn>WA;8PsQsNFi0EN%OILiJtK@$dY-"
    "{h{yp(|4=S6t9xCq5XCdiW-2q!y}zl@p?6VE%jB|faW+zuz3O1T&iH;IfLCHpV|5P+x*v0{N4H$V)v8(o69ezEQ~<FSyIjtFzx`5"
    "Bq>mv3bc~vf!SlPFj%#NW1)l&SOB|s$5J+DrcN8z{ZOua*6EEt@Hx<!c(646Gu#lGE+wmA1leQt)z|<@aq2|xayDV=pff!0-h5gA"
    "@%;$qJKcJ&XW-G(<5U}<Pt54kEl1LF>Tf?li!nBq0geIez-EEQh7^0oOK|l5^7wD<)2|ngFI~M_63a~4U9Q7F!JJ}-$845<)dqUh"
    "X_iubBbaYB&)8U$e9-sDhs(AmfU~&OUa=3URf6S5BmChVt^x{U<6oPp_IshKr4DZoU4z-LkhDym9(>x?1o|U2zFdHLwL5LEW?S-Z"
    "f&W>q>KY0VG-{)NtH~p#2<~BOPbQ4|^vpNfnn(jYRhG)o!FQanNgT0`+2g>aMJ~zAeuTXOw6NP!GgN&qo2_<TE=|1bVP?|0ZfY=s"
    "eCqc`5<85eM}Y-7!cEgyMcrUp#Apb~5XDEaIXL_L<gZ^BY`pRZyLRwMH@ITydCsj<#$c^39>i(X=}<4&in<#DBWB=3hF76}{9FHY"
    "$RGa6$2`5&t7a=|D&=-%^;OpZOJ+*78K(ku=n_j#;5<o-chw+t?Entq$e}pC+S4VHaI4u$u5f;EQqji7BJ&UpwbMAkY~+btV=BD5"
    "F?|k;Gt5{)Kf7)y+04&N_PXpgImBgY>4Uq3!^D)FdO8wqd)Fodh5-Cvi;fEedRfD1IW?~Z(v4S7f2~OU`>*Xk+ozvf7nqpGg~XSy"
    ";^WDgyTA~Mx&~GS_2nZW8N{VlAdCa5>^Hccv5Zj5u5L4UjIQSPkJ`Q11A}rewb^8~!#=?hYJ}NI;Zl5OhSa20H`xZfM~aCtGKUqH"
    "wlJzW+aECe?WMf^#Cooz=!nM(wgD=}4tO6yBJ|d3T1NYealxHE6Bs}kMu9>{Kp+0>6OF}-S5SRCp4WWKj6#9C&bc<wRip>UbSw!2"
    "3INKeUK=VFHcLx~9!x|_AAE&hKYt@r{WK({q}#kttJzPY*mQsm!X5+9ike$NaHui5=;NB+P6<Vg;-rc=s<hfjj_UIC$E^R-e)~;D"
    "bI;Wpg>SaTlZfz-(R7a|)~Rp_wNuH8>*V(l`BYO!FbtMyOiy#^`PBPe<DdJ_pZ@V(tovO0t3%lRNVZsMcXs#&{+kL}po-KH8w}_}"
    "EhJ#|EK0ckPQ5GjK}PNQ3;g3BU)Db)HTLzN?aR^6_8Sv@;cP4WI06u70U(JTKpN@zO$ir(HZs^)H@Fs|xVe0E2R^3WE=ZAW^@C<F"
    "d`(Bu#2~ymtJRd+=MrFnR2DBzx^(AeA_{1D>oVF(0jV=7q+M|B`ncUIuBLMqZTI-@g+f%q1=fm-!G@K&9E#{#OA#ht)gla3MlMak"
    "R6MSH@T1@KwBRJ>Syi3c1!SskV*R;6&>(=rZZM~^-_i1dFciG1a;2QCVf)w{+;FtwHQ?Jvbu)FAgi92aejM{VR{@Yn3V5_xR0_<r"
    "RJCH9V#x6H^~a2#`I&lnKtrUnv{h9{90y!YqUk=a1QasX&J2I5$r1XE!O=WuYfFwXeQ@Y+yO~eJFwmZ7IY3hMV7vgWUtuugBV^3M"
    "E;`7ycECPlI58p?uP4)$d~W~ePwngL=H3@BMxK}+7Q7QrNJ;y?)e$s$n-Sk0I%6@alnPnhg<?wT2Udz2u@mU#2TWeN7oMxOAJIl#"
    "A|<CJbqyk#fe=$(EI5EZ^uNRRM;T#>B}AjcrDAOUn9VD$6_`xz2xWi)NF(`Lfari6r{`9<4hzh|X#!E_XzDkmnX=8|vqRqR8-B~J"
    "YGn=a{LGVv1MaAiXCAr)Z-b8Bc`pLX7FuR9bDl&M?LdKFVwoQp>KiWQ@sXl-HBQ|!ajCJ@tWZ0Jps21QDoHgm#A>%J3Eaf8$}>-Z"
    "O(^!mhVPuVF6}-pWBvT|k9Lz^zYnh}%+GzPO2^trNe5_T1|O`DJZuopu~ElQYgzb$c26BpG^k0|0p)cX;6GyX?zr%V(Fb6{E0!OL"
    "2d|jF;ZHleW_^Zmm_rA9*V5Gjq0P`2#0!eV=PjK!#1sPTC$|Ji@zE<=n~z(*w?kbTewas{PVH0Y<qMDM@KdcS8wlGT_PdidzSZij"
    "98v4XMo435z0)z?TnkE>tu=+!_7R)+_NZG%@9$C9EWhPZEZ3;2wz%W+YC+V3+BC+*ikqQS;Gg=W9}N(a=_<-F*4DCeusY28fcaaX"
    "PfZ`oPP$b*@DRQq!tS&w&~@40_flb148>536_%4LdA32i_9eCPam!~O1)wXI*<CZa!pebI1oFKlR7Bl)#cxL9-4b9Z+2o7s5R0Xv"
    "K^-2(4;a4fQIff_gB7hW!9j&f+|Vvx2&&}KMQWX_ZQgH4ksja>x{VgNlu9_K8S~Q@^)YY#s}}R6FR8<LDb;&XCU>A`a{NeP72~Gb"
    "fv8~|+(KwUJ#C0_D^<tHH~!Sy)-G#yq|d-Cb)%D<H0s(~S6MAjW8HO_qbI4hK(kt}LE=I?jzz=nX4ZGjU8hbP7m_r>9-=F0@)D};"
    "FUCkr0q+7~t>js<;CcSPfyrhnU5&2en>OF_oH9uW&gm#XM^lpAk0V<3?kX8)!ez+uV1cG9$W~`T0m3qvZCm<!`(tnTOpPYkRtC{$"
    ">s$aX6ssL>k>q$0HR+uuuIbGru2`RTp3<q#P!-aJ`H0Pn`~yx=;31oKuyZ-;kS556aV(jYo4aaKREgMXXmbZ`LbH5hWX<(AO+GI3"
    "d^h`B`||Bm`}xvQ2t3-(Q5$ba@F1kC<fEyet_s6@LOxc#&VD0VVguk)Z&K^nCHV1<xeHH;9;!(e1HtfdF{=BySQxwnS~SvNQmwb7"
    "@r{#C75CM$)oId`mUe&N-W6AIarDYUh31i6rc)<ruNgB&jgD0E+4x&xoS8alx8e?JADM?=t^2o)zU3>MP-{!*9xBpDwar_}Ar<Y|"
    "%+VW@Xh1Zia!+*3?a(zWE=z%Z`e@#^e8X8>uVn2FPKX2p+wjknGhR_PV9E#8`bF}p!33kcYp6si^~T_fV{0EWdY)UP<~3RW?kI4>"
    "FIDB2eA3-KbI<_-Kw$PKFhdRFs{}~L987vI`)!+#bC>770DAt@EucGdpX)~N4%Kd1eE?RwX8M8j=c@f1&a?>dV>LdD@9zzA;hLnh"
    "bnK}6foe`URXSH4|6$dE6-hibCf7$d;}4j=F9Eu0`7dy+x3}oZQBT%`Hp9&dM8Z&O0xnh(#2TzLV0arWeM#0>-Ukc|Y;{h%ST%gm"
    "?1gi+P#bvIV3??w+o4&vVwt0wp<cqos-1PlN=PSJN)awD=x{OW9GyOH_lkQZhB|En!%kg-GutHHDN4atAk1R=i|Jbj$6JS&8PMt%"
    "^pM}^K+F9x<8L__F$&6Qdx}c*HkSmH#J|)?*s~0Q$K3&)r{@>z^ug&yyycx{nLV|Sy}>O)L^4(fY~#knn}dXf@Y=AlT2L+JYnEUE"
    "0T71T1j-Ba8qnCvE;{#zj6cfB{+g}3lja)dYwgn2AcNXQfPca7AV;i0I9~={yXwlYEHi`IF$*Yd>bCeCYNE)%V1E4p)A!D0@7TWL"
    "a&ePJApYv)v+KnB!puU1QVkW|-#f1j_f*HvZK{X4OsKy~SUOSZ<1g^Qy!OUh+;F|Lwp4Wqt*KdD59YRd2&(2K(QTGwYAPQaEc~rk"
    "*q$X)tF#b6)cy~@z<u5C4f}tE3tpZ2%Y$FgcmwRiCs~F%<U8<kWEE^@)TIuTC4y4$zr56MaH^)B_ri-VIKsR3ALxuXU*P^2^S!rt"
    "%PoD2Vdx@a3qEe&v#xXv-|EO}h-l%AeL`F_U_UcUF~FmM_&KXZomqeIRc`pE)G^7(X;(W+%zbH-z0YY_3cW$wdu%L%maGoaAX_nN"
    "w+>9|B?!>|y|;LngI;}!zrstOzWCBH4G6Tsh_ml=kFIl3s6fkkcHNOnedGYl-y=m5$xu1|GQkxabcrQ>z~lpc@zmx+-S5fpUy}%*"
    "tl!#L+|j6|vg_LQ0oyWfy4!3T2w^1^<W7}2Z(U{K`xy!oV@UY^h@+Sf8$RDJagvcTyI1YHvv%Edxxy*7`dIg13sZ|jX9MbW-l>vv"
    "H5FuZoGz{R?LN$v-tDk<?pHbMDY|z*=1{vj2zAdkq^`y-)r4Mq+rf&77`LOY439CL%Jo~ms15kz9p3(jo$MnoaDR_`?=2qae($}?"
    "t*w?3b6IJ#?o22Eou=CpiKQ5Ql5<M2U&qhesr=pr0BYDeoL+(7{Wss@z6tNWm$>bvTSe&F(@+_Yn%tKf;31Mk8+}OeA5NzI>|PHg"
    "w#`5ht0Zj|g1I;*eCjpweKGd`{-(?4ciz~%YV+RSc+2ShJ@A_42YTH#^N%U&c*F92z3ZCchvmK3#@`@#xF!};E49ZFrQbhRA9bgd"
    "O%Liw+hz~CtlZ`yKF#WyS=}@|aAdcS+I_5N{Utjbw_f4a&SEq%O;CfM0CZJcnr&Aw(Z-aUFrN?0O)EL~<h<@Jk#LwNKf>I0{xR#1"
    "T<d=UWx8y#_~0~hY4}kq{;K82C6o*Ee}Ttcyu)Kt%PsSd@wp4@f2GsCk!h^4$C<l}Ru>0wt`&Tea^1AvPF<CA);ZnoXN52(E(W&_"
    "1tIcGTYt#-U*LR?-b8%!6>d1dfW@b79o&8v9W2z=bx!Dml<Djs`5Tu)nSPWQ{cy?m#`1RwuP7z`8?W$iC-@7q&&}PsnY9s`W>HbU"
    "dfUY=aRqglgB-HRF~6rTtaZ--grc%8Q<5~Oe0^$ld)wZlmiuG(>CUbG1)1fY9XjbeNyxycVUTtMc+$?hu~HoP8P2;bE@h`n3C2v$"
    "A-;9X@6?!A4DVQd_yT@zLi-@pbi3*8ofhz^!N)D&C#!$K0)8_6SVVMY^)Wf%$>?9=HS60$oo0P|tk0}(e}T)aZ-14?tZ$EBy6fBH"
    "SMGD~>We!HDHVV@Ybd9d+>~~NH)@v(Tp8I2yCm%pS<i%quw0*g`f8a2m%Dq<-lNv;slmrB-Y2Vn!Rmc7eIwr6$$AJg0raI%lBLd<"
    ";_|yz45Y~zxT99URI3I+5*o2ly%AXtX6}z!eT>t59iM-D98~#X?V;=FyUo8~6@54SSj_Os<|9|o<D%~8c{HDWlHj_+6Qd1`<k)7E"
    "YE-ikwlz!R-Au}ksK|iwxtN7Q*5QN2QKQ;)xq7)ra$)eY|GEn-Avaq#hwS*AQe4s!tzp?c6ER-(bjg^WlM7=VcLQTtmABdBBNne!"
    "73V|YcuCYM<h0_nNzxWZGOKGOf|AM})Yy92?6OUre^%{KP0BOxnSIM=W;c@IWO0r<1}v>rDYq|QDsj+9M=Y?7*_^?yT~{a_X1;X="
    "a5<Ord$w=64Y^BMZsn9BQC9s8qFXcTrr}(<2MIn#iL4Ek*2T2fZY`DxnKZ6`(CnG#Y}3@ot@|+KA(9v{m2B-;wVk1t%(JzJ%%p8Y"
    ";>C(uliwJYpg-TU`Z(t~?{ojuHtVfwj=uc{nXHss_qM{jO>a`?^ee}VN2$MTFR}R0qojrV++8B)%OvY+`FGyo?$G9gFY$mh^?^5e"
    "%Mm4`)3#@}b6KWui9wQ{$jG*u%o=qg3}XGxsm@%+^bVKs#C`%oytp{|k=MCZYMdpQNjjTl42hLjJ2RMoWn<PfcC@g&uu<fV42xB@"
    "Kvg%Q`(AmsfB#L+-PJEC4HZJdh%T)nVJjEXN<OFySPaIS<K9DRaR%NNM<#%^JhgkC{*4#8?ZK1ruT}1#x^kAwm_=7y?H<1BZc)-g"
    "HCyV6LD!epY7Q@R#O_k+`7PdGKmWwX>Iy>tdHwYD_b&j1D>;xavpE%AwYI4M+pOBGXY7(ER+3CT6QUlKE|ZIZHa18UmbHWzuk<mi"
    "7hXzC$f2aF)+o*oTyzxO&>fx+JMJEUo`_@F99qg&H^Yl@%?;ui?(<=@R}21aU7Pqf_o{YvRv>xLSe4Zp2?@sJV{sDJZ?^IxPVHR0"
    "X-z1g?+@92^C~F7Pz-J}inTY^QWW0e<E6CK-7G4*m$EZ4RLZC1>f(IGYrUPRf9M5n_+AWheiCv9zLM*z?wjsIEYpt=t!^DbDuJ3u"
    "m49hwXW(X-Ab1bt`y;l`ye*U9b&r;@_N-pD$Y?-T$t`v>oSNGn-8EB8YNt_j%S$m)#qYBi`ytb}{p)|G|3kRloBrIjh;S>l;CCzD"
    "wH;W+uIO965)I>7y-^p*QhJ;@TjEfU8>GDozjtw?;?m%~#Rslhyubdyh1my65M0>4rHk057Dn74r(*_A8zjOx(kQAAUU0!O8UeGB"
    "K{CO_S7>0?5|tE1_@LP{4+2(!ol=u*tT450Y6-o!G(Lwh8}?b%4<{V=0)Tq0NJ6G$hT6Ee-m`k!d0>1@BZ;7~Jf%RpNYGO)1x#|e"
    ">_d=5#fVAwfsBMyfg486l{(Apd@U;-N`MDo`^%>*d%3YjKstYsm<iBKX**h2dc6ktXzS`Y;SuVV)Sk0->)L2#TQUb^;vI9BJ+45Y"
    "inYl}OJ}FCS+xX0qv&tI0aFb*uqQQf$8yVclLNgP^I$Z-Z|{oRm`3^`q>mBGgo+)_%B<F|c$dV8b!ERZ0swSBq$)9)(&&ONrA_y?"
    "(KjX8GRU(sk!li97j6jtWj^<E19k}dSaadB6<p40%VC2?K-GjNqG&d6TfX5k3}Ke~f^p>8?5AYrm`6``l{zsP5Conh3`G}OSg^Ac"
    "qO+ZT!GE{=kkK=TVd<0x#rJ?UZP(x%d8t|Y09*PhH3aX$B4K7$4jdE`1xwuC&q^q6Z`*vMVpokX`WDp&I4w8h_br419ceXIshHy{"
    "x<{O#Ons=y5_w@(7ep5>?CR<8Kyu!T(JLFtZmVYlh|vP9)fS6LoXG&JSosj-KB#ThnwstA8H><HBqyt(e5mcCcJIx)-ZFfDrgh8u"
    "1Gffmy~3?Z6WvBLkfoVb=Lo)HC23b>>^6%;atIhW)zr2jp##V{)M6odR{YHEk6FJjuDfOY4d%3UVJDJj2jMAdTOCB@-JC3Kylwjl"
    "u!UMl&dYa=lq1wHU8*!hhqD*>{nzjE=)A&<gI!)-A;pq%;g8dZAWJq>8ohycaYj)l1Sfs=E)4;aA=oV2RGD@tUI-sDdT&3wY4!e2"
    "cGdI)J?yIeTN@TT1(-3DX<JLuLI4H<9y{5>M+kCu4dj`m33sUV8Gd!A)q@mFFNBfbGJW5z_^Xy5wyAh({YfME3idm?jTtg0j~*=F"
    "pq{%8lnGa11u)?zf?eDsU(Td6QkUJHf}kX^{vo6H*1o=J_5RA&S4}@q_xh^+8;+F)Wi4?@?FINYwO>-BJ;StiR|zC`lGFH6U~Si#"
    "h9|2q9!)*urvC$`@2h!z)$+p>ug_Z5-}#L8%-a2P)VaAwB&SoG56w!ahHq^?z=3C;aMPM&YT7Jfc}ljtE?2kY2YOIj5Wo!+j!P3m"
    ">x7CBr7w5#uiCtK9y&Gozy$QP5C7)Iop!U1ojKzFq4|<B>_7L(bOIzh=+TWxjz9Xs6A_~5to36<-t)zN)(xxo-o3kR_WoOV*KI#="
    "AMg4L-0&x(et01e@C}4Wy7W~_p@Qlo#5F6iC8S+SF|5S`hnW0ww1naf2r+-e_BnT2J^?b+pi<ps%OJa~wA9(Q>Lg<9q>fD4^%2#c"
    "IZap8rz=&p4lwgWrvD26`rhjKN*^IsjT;RZO<J{pw@eZY13uard0+)p(W<-cv^jw@ND<br1x<{}oBpoB`)8vo79Ww2&dk0kXwB;@"
    "bE_X7Ak`j?e5>y+wg~Ew{HPIqY3rz)H_WQk<N(|WPLtz%wr`1z!fK=Q-a9_TnWZkX1}E*U`)SuC9ZB=lJMXqOB>4VV_L{Et1rBi^"
    "G<)yNbY}IhaGvjmuAC@AO7Mj+)D6BgZNUSNL5*roLWZgxtS(h@*H`Loo0wfnJNHd8iK)MD@qzAhV)CK>^TX~#LEX9WTOI_}?NzWN"
    "XHp^lL}qBwG*x7gh)w1%uePdU#0*X$N<yGuD?{CYKWg`3F7(6f8$LA20L6J=gnAez2u}k`vA}~5YK+H!E%9*(@-DU4!N1Tcs`Nfv"
    "zh?T!?&0@!b)&<UF^;4%$i91R@g0S(OxjiBT|Qh2*H+~f>h7%e(Zko~re%p`b#?uq*++QO4ZGLQn@roW>O9h_?1$Nd`vq2VS)dJq"
    "M@=k%oNZJS@eo-R-50eXwwa0l;8;J{udckoEtF?1xd+Hh{?XD^VP{BF!g&Eu-6jZdcXFp4tAV;<z$*nNLu&K9-ybr5e-FE2`+=$I"
    "YumSUduM8?HIv*(qqh)NvSa7ehOWT&eOyU45F1}jTG`oJbL*jofl1JPc+1xP9qP5QM<k{fiw||37qhq8XQj4=X|<QFBlVPwi5}V;"
    "e95-&<zfJVK#7XWweSwJ*ND?tpMCKcszX;So^zoY`4-5n2aXP35?pZ90C<fyw8a0gboieFS-@x1v@0t=rkue*+q_}$VV?0{Up~Kx"
    "(0rGAx&q^xWo@bpisC}5+xDZ4^&Apx)IPKj-PD<uQ(eG{18VG2g9qDwA@Y3H=Dj`TmeFfH7t(}E4<c&AL9z$Bs&_<F>y_F~UnYI8"
    "^$aQbF={Ez%&pZ8<+dOC+y{EjHS;%X?fT49LEZZ_+#CiJE@fdqv#~>mfy}Aem#=CzNf}gEYShm6AnUe|TfT3)xn}r{Iy<~^swwdD"
    "vv$^$NzCcCDMc19i<vM{CvT)U>KSmSt)(_yke1o@SB)PD?zTtmKArY%0K;YykvDwPSR5+y%&IDryywQ#wU;n@S9OOl-RLCuZpue&"
    "UU<~(zy>$!+z>LHCg3{LukMqEIupI-R2h+n`MOeqYE4%oMGV$spZkMGuXxm8`SOjKxWuyQc^$Q?QTrv)5vgqE+fq7?_|;IJWu=bP"
    "1Mp+!wCw|y-;{_SqjWMkO9d+?R^lSiSsJuDl-V&8+;(BYfmY4>Fx5M}7VEX*bN_((TRYzd>Jx1<r7+(s3`vl)b{5Mm)=*r{qqSZz"
    "+O@{j!)eYy5Q}N}<v(uu5gzs0@Pl*I^Q_+Xs{i40qnmagldG;9zCXgdW&Pnf>+%(Do-Y}|29Vs=90^{t%xWX}yy05`#G+mgf@*22"
    "r;mCwFz{ZRj$4`Sk6C|&r(GI<u(y4;aog4UvZW6*Sl($3P&N|@_8E~FK8na_4X%imw=hZsR1_av-Yi00+^HWj`WQdEV)ao@c4qqF"
    "9(HE`X0cu~%LP_bYlP5Q9AgpOP@RL_%ch8vsr5I>ET<!H!+wfuBeM)z`2(gO;ag{xZ#$L%03W&`1BFOoquT432{;x=(V>JX$1Yq9"
    "Ww*M`jC}#4>QNMYQDptY`sdHzewv^DvA$j@BUh3tOHgczSb5mvT5_yl;a*)0Rn3O1s`(ozsvnomtjT@h>@(T-Enb4coivbH?RrRy"
    "nFr=pwZUYpGn(yC)ya;jH>#yk^}0QptFYdd{g}yXB#RH}#i&RIx^5cO*hIXj&Zw^xOftK}D#IZk?5grNpIC>kB8~B`-8T=Ma`7Mo"
    "r=z{nbBLwud|3C?)2fg>Ye5pcQ3B{U^*qn3swdXeHgA3Zqi>azk5+O~_jY2W^}@DO2e+<O-3?HZ8q4is)nIOeRV-j;4r@TA+V}jZ"
    "-G{i*iP=XdCz-z8jd(!IBQb~pF2ioVdpqbxz&x41j@3Z^g<KID#H2C(yF+(MDGW^y<|8&QyF=>ueXJ1MV7+?Sv#%@}`1I;6C!mHV"
    "TwZn5K^RBioG>f60b$gP4;sDVNi3BdLJ)n+QMXuvO@0@0f^7-EU0X8aHo!9_-50$wbamSQ>cg&&4DnmOlu~Z9!EG?+yW~I^;%>Ti"
    "psr;CtJ|erja3f{MoE`+)rnw&$9hcp1LkivKu}YoUXFgAtSDC&EWR5nQ4*Wg6qob|7!16|N}hy0;aiizpRv}9JDG1-ewaUfpd0aB"
    "JnE3TcrdX#v-udXcWLxdSnsvvheN&B=5Kiv?8r3;QqHX6o*-4hs+v@Ftj0~&R+xEL1(fB=PLW|EXY~Rw=xu-8@*_Ozwc-1F)DMNZ"
    "uYWfXBW>!`^8fSpX3KRXNw(z|vD)V0u|@hm_DlbPjTx*W0bT&i>FaxK2LT+w&q0I;C2wVAMvw&E+-*?ZTTOMVA9l<nnE>AsD_48o"
    "ET0?656%vYtIoO8bs;?gk;zet|8@8C$N&6Ip~>HT(CN*rlZ`Z4!AIa^nq8%3AluA9@ZqAuwH)0{4&&Nc1P(RF&s1C|_Ve}4e)mDA"
    "H*;2!K+^;ai|Y0Hp_<tSTS0gLIA;<26K!O>o0#yMB{i3E?7J-={Og<j?t@Nm7Lr;xj_UB=kl8BWScmEA<{j0(d-GVefsuZz?0|EP"
    "bBXy=dVm?PZ}z(nI=xv;65od^93?y}IOQV7T?^ZG;0C8uMa#&_K5x$BaFv$^{BeD_=-*cJcOP_qGd8E2qbDUFSPpB-E~dECURcuJ"
    "=T^<_R;mOCNC#|;4GWpTA?aAWz1eR*==5f3HMKeimo*EMz++)<Se9il0Lo2i+okC-21P8Z1k4|n*QdMyQ0wi@e)mDAH-k%p49AW+"
    "XWWZQq50`x4kX(Zfp0qXwoG<v$V&NCajNY~HU;;+zS-|S==^5WsE?{Majoh&HO;Hg#AEUC_1eYVCfwqXUXtq99P<y>!xtM+gL!+i"
    "-+a*N&1y2zo8U0%5s~lMkt4Qitsa^<GX}J0WoA~P<5p&E_;w%JMHq;;6Y#qaI=xwI3B%&2Rav<K#uzMeADD8hGHG2fY#n^n9Cm<="
    "o7SWxIghytPk(*0-+j>O%^)Um7frBJBrarI@UcBi*ml}w?lB9G+<F{14^zoj!5*=1s>Hxw-|TlEbbhmnJMX?>g>u@)$oiB4d)lqk"
    "tV&5O(6HG^`6fe&Ljj8^BNq>u^V^&K=7Y{}b`&kl;-GfZajI4ya7?^j1o~wM_=T_!4p3nQ+}w<~>h{jEOLlE<Z}yuHI=$I)ep#3J"
    "n6y)Z-xa|bsk8UF_#0bwIIXIXG*37vL^s+h32LlC9O3oNe)mDAH`^+gb-MHOutG3GO*3`p6*LR#55o?XK2pON0`G7z*7{YPa_N;q"
    "|N3UX`=IliEt_`<7QX^cIW8P`PaJr|7TC%gS(`H+D#WI>k+$<?dpL8PEL(AJZ}yuHdU>;lwbuh=KnM+3<&5(CCCk?LPPMQ@4rM=O"
    "B5h?U%>iCfgH3JVQA>o6#Nn{(_P?I~`6PVyn~%BjW`ImVZPj{IIQML7J=i-iW=$}9@fOck?1Uk5=$-2dKN#JmTAxjczuxS3A9MB1"
    "W{|XoKl;%|I18pvEzf0j@V?f#w(-Plh_ZZ41E*JJ#@iIm-8Qdp_Ir=H@@DD>p1jwN%@}TV3eSgc#xzH1GI~jbK;&`^wz|Ay4Ji~S"
    "G1akV|Mh0S`<N?l7L={ynR9D!YigA3a;i2TcW6cobS2Pyg>=n1J=`ca6`fdJp?UW*XTSTHYj4&-pb?9V6H|P2;9a1jQ)$K04pZR4"
    "ux$(5+cmGqgG(U84INWn!ONTd=3}nBSp@3=30h?xKqX^?K9@u))%G#25ax>fnW;qq5ujj7TbY>60Ik?ezuxS3A9Ll+@^K{rv;zo)"
    "qT*v4JV&M*SpZJaw&0guHght~h$6DAk6P~mn#YUP_}#}`d$a0|4Q?n%;Q5<2t98X>f=$mVRT{cp>3*wdNw*5cN5466Q&zI?mpA*("
    "$6R|e74QbYaLY@j!Ai*(+Qfd_x|iCT_S_ZvS)8zGNA!#T<h`0v>d(uY{pMq?ycy6qR~&xmZl|u=<!F=cmwd6sL40y?7J|!6I4?Qf"
    "7?U+knsA)FJ%7E~?>^?*oAnv8dRS~ob%Be4nL$o*Y&ND*e7m>4mhxhw_a=lIr0kR|bAYRUu^PYom@9AAZCz{#SFNiCYzHv!sVYMe"
    "PNA$k!xK4aELYh<VohCf0nGPW$%OIi&3^YW*WN64sbhnzdRElkK^m6y(rwP5`MsHL!-Fu@>>2Pho~F;F>Z9ROc{!WE`<QEQCaeoV"
    "bPZCvRtstr9V^V9Q?rI}Dt;N`SarwQI{bD!ym0ZjJ`ViLoBifvuDqF;LpIadwb++KLKXaVw;Wy&ga?wskHGpT7F6O^ObGBbm661K"
    "{fiIy-N#&cGr-*#jj4xT&5?8&?u<fjo&DiU%tP(@jE6%Gj=PY|krxVk4V!=e^=7~Om}_s=YFy>$B2==E9IZX`mTr=wmuVUJSdbid"
    "hWB?LR<^VDfYY%&*uTEnZ$9Sj&Hj50=?gr^WMA)nZ8B1gUK?Wrd^TzqU?m7TIa;x5kN1sZHf}UbX#iZ{mgeq7@`D$f<*9wWJ3W2_"
    "JC-YMMki6|;gsiC$6Ui#=)o#RS5Ku!$zWt4xa4hGS+&}sDCP6x<Nx*l{jdM~|M`Fa*MEJVdgY^}f_KAUsv1RdTaetz`mrA1{JI#!"
    "W#0jcVXFR<AH{6#4w0Mr<(bcl3ysD4^03DG`s3-pp4Rst>a+VA`cH97F{AVLP4~i@D$_mW8dSpOjW)A~VP1|`7|Lga$*QKl_S9bz"
    "B|i-H`19M_1g&7Z(X9+y-}^bhm5S7c+EUOp8q~l`S<_2WvtZc-2H=B->ehY{@3<V{^~s=<AV$$y(akR9obh)t+-i=DlXimDSp8Nu"
    "j8Y*Wa1e0E_k_uCFHauralOUnCHI7(Fdb*VI3H}!#sB*XWnL0oQx$en8Y|9B+bBopz*5sTFnoM@=qvZ@-`d^(d|Che!Mr@{*t|rv"
    "?MOZ6upBODE9Q>P>R?p7qJW3)0sytxFOGr&?T}!$e~NAG-P^5^_SbK3OqMfJ>~>Npg%FN7mN;!>>q9CQh5(FUJwE`;u0mirt<DOA"
    "FigOX-WcQC`db_S`ttMP+v`Y~zwSJ4Ym5?%6rEs%5@lJYN;b4NCtZ%FHXhphLz+;W4WFF1tp91GaeueJeH~8{#=jiMxD|}n)?v(*"
    "(5s~n8NbPiZHF?evWTM;>i72S;jThz=df}ZwSHxwhlig(p1!n)@yFM{zs;S}gjo(BC$1T0?}KZr#@vgnNbHuK)CF%k|KNB<ar3C6"
    "_X-O!=Yi(a{PJ?m`x2eu48;j|GPY$-voc_O(bZR+SRl@{!IoGo-yBszUiK|;PH7?5*4WNt{5%9-pVpfW`%A#FMCK*{rKP3<_Q|Q`"
    "0QGKtS{pLEOt5-n2H=>t!A}D&nQ1rk3iUM9+m`;~fC69c+V}PN<50JK-F*QD>2s~hP2gA>xNO)h1LIrNof3`(hlFJ?(oM!P^G!I#"
    "-c<KAKO6GqM#RrS4rVKP#AYqT^bk#qEBV^N$4z+%iqp8*UEsxCNV_F)AWoSh^4Xxjh8y?af3&B!fN7P+s1K%<P-c@tLgoLI(=LW}"
    "6#v-hmCwT@IL@^!dk0WKZb0szjrcmLU+^g3+QV_5__n4JUOpT(tc0C7c2q&gsv-hjBJx(wA&nyKx5*rb9#V3ya^_dspN_o#u^wIo"
    "y5E9!@H8wQe8}RC+~}$eY$Fc~@X?LD(qC$8(N@E|Y}W(Um!l)a-j+VyMR)gC_7G15xJzObe2{`}TAIXFXIGF_vdgg*d2Qp{-t6VU"
    ";Q@Xo6^|@yJ{$1<+q^QOZk8ceUcq-xOW=#s=qk_9MJKG!IhHo2XPs@Zl3eAXZB`qk`qK^c`18k)`v-xPj}wb8z}0u73!I_b2arVc"
    "QQCaC-wI-JVRbo+1Qa-WF>+{HwGqZy+NVqT^sgW5i@e<1H)2$h#Yc*5OJpG6aEo<2%)09iCSXn*q$4!lY6d0SmJlVn!9QP05U-E+"
    "B3;v-o*usTpHJ)J)(_XVQ&hfzxAEvSDd;=1;^$yI`Ty<!9=0jxU~!a}tY7aDgU~)1^>qxtTkvHnoV<EeNDAhuv>#3hzW{Vu<?A$1"
    "x;h?WnlL|@R8_=`R?i#soj(m(_wO;-p!6TeZct1!cV(g4KIWLX=j;+DXi1B>3_C18WdN;E&GQ#Xg5>Mp?oQTvC>VJJh{jTF8?Rp!"
    "C}qwz;1PNOa?nv!y257j8xJ(=5LRWFZ+CN`@4(pEp4ykTpVq^h`(|dgNz+X?N^xy+<^})(#yky}vK0e3IPRW~!g^)JDEF#JOmkQJ"
    "=i@!gty~O<2^@eryb^f1Oh5vVij@I_Pd3TM<3*ev9^H1Q`mdd^<4da1#_gK}Dy`|l12JvQu-l<q1{lD<%*w}_s75LZ6-o}dtaym-"
    "ron%8*9`wK9J8|z|9bcL_U-HZ^3U&Y9w)&md3Fz5>d$!S-arDt=qO3%9<W3f&zHv-2RZ<H0m!PPf&oJI41KP6wTg@4tmX{`P?7`A"
    "-1n`h1uLIaFX!vtN_S^x`!xe@m(AIoB;5TKGx*YTNVehPf{n?^SRX)%hrrr2tu79*5T2dU3`ls&tq%FQlsG`(V?1jyiW1)(<t<kN"
    "K9PXf9Uc?6TKIDEI5f)U9>aPic}w!`Xt#q|U_y%z&t7H1k<SCDqr{JI>p7e4?&sr=^_KtO``|#NI0CFJ;_-3&u?=7<Ok^#G6;;fP"
    "jmGYl0J+DI>i$F+Y=-md%R{{%!Y+W4?2Fpdu%ZfOTG%6QkA1E7Ne&;s_&wcYHCErZ&Pgi@&b>+oTnzE}vv2$ouJ``#+rK^zH;x!W"
    "H*0m7e>jffFVKaiL@*BNDpRz=9a}5!$s+Nqq4W>iU*rHUhWmN<=91oRg(eMVTzcDVZe8Q!%RQ%vd0dI_1*qoID=x9)jV5~q_{%qP"
    "pkTWB^?cr-&D{p9|IjTdt{Y%ta0?uGc!_7uhReg$4w35^Jw9mY>Mg37*Gv`0_x$+ujy6|=Q8u<`Cv{Prcf>5N5u)E}o3y)h!?w7C"
    "swwxt5m+dZ-Nj^6UM~C7U!u(g0@j7<wo+el+G{`y<gdUc3L5IxA;pj<TepIwqXU2$)39^v#ml5mXmf)-L01MG37Eqg1F%}R2^<HZ"
    "RSJ*KK~m%JgSL8Q-HS9hv7(^>wa+8GCL2oX2EV6L&l*!wSvnp@Q3>mDH&(5K#cnzI&GhGv+e&o>Mq?Ag%ah;HW-IO$yLS><UX|Tu"
    "6ajY1)7*?=l?tnB=H__QU>9e5s*je*iSK%S=vz8Ne^hGb8}8fyEr(rI6L9_xNMRkY(uAD~wnvxitx5fzal;Z6ZU8s6FUvlkp8w1r"
    "E={Z`cbvQ}XLRjm%TgERessLS)hjIV+*Bs#0U~2TR?9=|z3)~{It}rkC6?(^VmXvI!qSFPjyyOpv+`GWf<|C8Ky+AFBQ3qjvh5&)"
    "KQq%A_bSG_^BAwh@`9MZ&E2f20ku|v5*Vm{%+?OZ)340V#kQ#sSX4O!o(cQN;&)+mqo!(~4ELO&JlcgX)XgmJP!iRuq1~!#)h8V3"
    "oA^~1IgHAaQauMm#e+4Zjpo3ZC7IJ;9PX$0?pAx=#2j_|Zy}1(j&i}XrH5=Epah#CDeJ5_N-0sb_}gG`*ok|bx7!Okxdw_ylP{n6"
    "JLa#zUTR}cO)L^atiaa5i;oVu1f(uFYaMm7l+H;0=jKp1kRCQ7>dM=B_z~t>MLk+B1OJ68!&UJkF$DIzVri-CGAY67aET2P`{(0*"
    "KzcPx12=<R49L-`DqwSr8ZUuAgea<|AY{~rl@^=9DnbBFFo8o~#_bP$SU>I`zaELquc)#>8XT+%sA3g*ni$8S%kr`~v|vBTfynEU"
    "RW{3L8ZypkNENKzUblCsaulx?lA<Ysc?rNAE4(|UquODOELfz?(4-zG!E;p-`3M6BOP{~!8mfdzFe&)=tnA>e`?0tnysa-|Bt>bI"
    "N$N3%@D2F?ESs~CBylex!1D?I-oEiQ-*Ls4J6%T4ZihR>tLHR<CJHG_#}fy!D@(yMi;`AjRLw__xr5xe(%#wtrZcd-90YpJAziBc"
    "l5fDnkLqSN7{36pjOr=ove=oIfdiyLsC0HSZlaHM9^^CFhoQ!VGZD(K+HNnC%%Q2zhR*6yvLvY2AsUbhFL8c&HZX2#`P@DmqqiUo"
    "@WOmCZ+Tw;OTeYW&s23L;zvMYU6)cpZC{ddt=5d&v+IEc5YMe_@{F;Sa&!26DEq~{C0R02Dn-j+RtIVDj97xei@Jue#c(EB`NtAE"
    "Fzk{bk!%Y_caro^{m+K7Z&{OLs+47nhK2S3&1!O-WvD}kI^tp4p|**G+kIp)vrnl?>tTcLLwae_cxx#4#iTcDG>r3VWV7qc>e%C0"
    "gQB_)V|b+M5_8HXHGD|ogE8em6i)ZXVYTrmU**3T`v%pa9L+hg7v)L0FqHYfrb3)E&J4Ox*#WkG1K=VEuXw}fgf6YGmoVMcp{~W|"
    "fKUo-FLoc4yl0P}1@GeTAk-<#G)Pekgruy%6?I)0bUEQH)XH8N?mt96E{6C4*8E@}*kehRDbTMChpr7$2}pqvuo+`?kc5We!RZ0x"
    "Kw4vfIGj3mjSf7H=P@4cbx)^34vO;@*jG&=SU)7S0!@K~R0bqusn#`MJq)Ou$pR>WB9DfDF^CHLB)R9ak$6}@c7WHr?+K73JcIO$"
    "9bgZzo~GI}8PC`-86~eldsOq%ILIKCIbB@3f@A0_d;4?3=5v>gXlcWrj1CO^qgyl79Z<nN6AllAS;9{MVpIvcrR*C+fd`$2dyeJZ"
    "e?MCKyv9;iwW%FNNa~htV7v`e(5qrvIMyATH0wiw^Yo|~819iX5Y%w3oWJRI2v7G!Nl0}l$gBz#p9M6Hz<h>IIpOaRj5;zK)%CR0"
    "l};QgFxIatL;dfc_&zmpeM1Zl#~fK#XrZo4rSxB`Q*M{(c{d&oS7&)#!@xPo0Xu$U9Gd@7)+>V?dx5R}ZpY1|y`ayMZ0?;ihfBZ$"
    "%sD}*!j1-FB}qdzhaxJzcgckV^O!(Z?mW)r!NL8HR5>ag-iHHCphfjW=r}<L+7Y$S6PAI`Ymhp(2Y(7HaO!yYI#ag@v|kX+x_29_"
    "qK!Dzoz(8S*=j~k16Y!sv>5GhPDSNjamtWYRPkCPpWhK^9w=NsX7akNty7)-fM_vE(~LvFfy8zy`)(Q~`#@EI)<HK@dxrM%%)daO"
    "`>MkI0c$ILG)z`hpFbSGgtaGL%@iOg;HgXL3Q(#ZpLJlxpuI2Q?)(XXuF4VM>FH3S)<xPL2ikNiNY`*kzffp!ibSZ^O~9ISYT2+5"
    "!Se`jJ&eaRl9+B?%t>*!mBP^pY*w6ClNj4l4HZklK3b~$aVndy3N*QwC%+@m!Qs-4V*7Z+q<f*VbuY}`pD|!X8b6VbO9!<Ct#uiN"
    "v(#S&uI*nRdO@JO%FeXw-*8xVu17^ev1CT+Mq9x_b2QZ6S_Y`JYjs)Oq;r5v2~5wBG}GQMP3rP(mcH<HkR}fX$DB4PHFSsR)DD3}"
    "1f}S+qzpfjw?f?A?i!dhU7(*o;+ds?G<Ul2$Pk3qS&8K(SHKD`))|n1eK(z1fwx!H$$%<~ZrRtyJvn?<x-rV-;Y~8x4tfeHRs&h-"
    "VtN&@l$Dxy>d>6bkyY0MG^1<#hOMdf4W@pcsQ+v%Ab%PQa56)X-*R+l$wk8O9Ug2Z@E2EuF)F~Xu6DH{Wjrm@*>!T3YOU>gj89_$"
    "ITyKtGNPoGd8BSjup1m|?-~c54?P5J_x38Qoob%apzIKOh0Q)0?i>qHJ<;U&WvB|q4SK&;woztX`UXKcCyUtvV7eADz|ll!2c)|5"
    "=VgB~*bAS%D2ypVbG5SC0Atxxh)N?@cRJ+}C0<}>kX%$$1C)g~QuYOwEi}K|Cu2PVC4X)6FZ1g@Qmmfd<FE`t-_jTY4zb5O=y!s>"
    "@Q@jrGd)&+X`>!(>y*7>jzm4ro^d^#7x6jh@!@FUM5RF{Reh{&*1a2>uDGTGAg`h~3v}%%df)~?6=b<2rm>X=gCjkS@*4N}c7OM`"
    "N7nBmIKK^uzKNS9-MzrPFgh0VwnR96b!tNh{*SzmYN5=6_W%J8{GV?RbpkD3xn*%Uz`-tTxSUK^SI6zadE&~w>qkbI%Sy)~K;Qv2"
    "YAUHa$bNIE8zB|}`Hj!Qqwo#tp~jlvmzypOflpZa#7F5mG$gyA0%;TsW8^@lRMwx5_aVeG+!zX_@d&VkE{O|gY8K3i?lh(U#)g5A"
    "3`{2H(ahC2r6r~%p{m;-cqPPAl~oDq0*!B%8i)h#>9@ze!=nW};PgWwBm4&-rvZD_qLP2J)0%pFtal+6C}oRk?7*X{v7-i<1pv%q"
    "9kIj>4;dEz)hlTPpjb-AusG+Pn!DcKh>u_Uw@Yi)R2HHROG$ipga}vy0)X&RfLJtLIbgL|PR@CZQQ4$Z4P?}D{j~vRzKrFt74F)%"
    "FaP-C>(iBl7@!@GVg6$PgqPW(CMLsuzy=(n0;a<sj)I5F$|)!?RS)rZ&RrSoIdJqYb_v*Tb8MWTQ#O}M9*ypdotuItuGi(8QU^E+"
    "k`(V-GD=Rl8sLk0bCApEluA_8)^877I7i4f=qo<AWASv2EO|>CRL+7;((06A_ELM%!5&TL_4&5${`U087k`1Dr?61O*@B#O#Q_|}"
    "3+|*IsUT$zENDmyw{v3Nd1_PlbF71qbhtUfTcxAYzw=B=@L)Y5osu_*;x`>|-GeF!bFli3tUw&dxQ4bcA{&m-`mG_tMbZ@;Qsw93"
    "cCAR~)Jwo(?aG3%#X7U@0uUzS({WkGc4w+?JG?yc%@N+h8muJS79y$UXRRyi*|X9b3a9SIApz8Jy*`3nl)B=S2JGgxY7v%i4UyiK"
    "!jGV87NID-bc<?yZjKI?_y921gfnft0bUTJ!ka)rvp1tpuZ}F^<`D5B&F6^q>ef0QXiM2}e3p{$XZ6z2S*l+VsMAMnh*(v!bx}e1"
    "KCkvm81jRI+gT$)A+QxY$1wq`x>tulYKfp~5f1}Tx6Wh7;LM=c!9<$jl!tS3oD*7DW-6)<Lz0-c;*d&7RUVUO$mmYfsI{!FkNARA"
    "f_1h^*;o=BSI+vUG0)ADs%No{y0XP~WIyRvo`rWE6xX$E3e&LH=cu>`<JC8~a%##rFVXFoXYv4I<CMSyrsN~kEp+PQmmTY7b*1u="
    "ZL%c~-{w?i&DIXV8AX0SAL?DqGgb?4T1r4kQHi9x9|3&JGO4Q3jmDqLgijF`i=|MXmMkzCM#_IS)J4p*Jm;hGqVRPrj{%UlIh?W;"
    "t*$85+(1osaGFY%ZwlpOkkqg>wzxhY>RrqeVjcHZf?Q<3fxS5;2|u=l5xTmfCTV~vtq>H_iu!2@Ohnvh>NR~n)Vr7`bX0|TDwwrK"
    "ZI*F%Tk@2dqa`qBf`sT5@zlySWk6;DEKCvx&wMh}wV0>TL$Evv`v9n7H84leZO49BGC!D9)J8fg%O17TDw10jmOG`ia2{?wDr)oL"
    "5L;|-w$LH$vrB9=u{>xE&;!fVbB7!`FjhVqyJ0jUzEpq10V>^Ww}!cbcFc(Km`!L+>bWXd3O*L4`sn5&C{uRLDT}SUO`SlF0=V1m"
    "x!0Ao`VU2M-w*LF;%WOaKd$hP+`%r<9|@eyI6zQ=C&!k|K~0e%ZG2Y3;7WvJ>@oJ0=imLY{(0#|)oa8$Ouii=#cB$H(byf|JuB$1"
    "@oec(3{`po*Szxaw{SdE{`CBt5#m04VY_-Yc*ie0mig%E%!y<}%%!UWq0KavafO+vtQRLKWg8TqIgRwT;9u^4K8c>3?KqAZx{pn9"
    ">|2hiGK+yA%>JR5#|ho_xah`DbcW0uUK^|0(iHUp{cO;u_0Nm22Cv#h-74P50B|rs1vkB6egpCk`t(=~w-Y2Y*tD5iAfv5zC*2dD"
    "273IX*)KnT{8$f)G<|sv?q7I9Anr5)PK$+eTV1G)q~dUp%&<bE!>$421mtsSx2ZT4iA%@TTOU`4d&7syBmw+{l|81#sDiV>Ia=e5"
    "53d)jK0*->U9T5hFg&6;Tm0~$Tzk5U>C5-8|CBwr%w>&<a{=d7L>1C8m9GdA!3-3f+z6TRrzls|{gwJYP9=wg3Nzkw*c(G#<g7vM"
    "w>qG9T_@H7Ff@LtG+G7rDjzh!Y$d~~xzzNM!Wd4y#e?$C&(Ht##z4`gS|%7p&c+3asX#y2>Z!zyM^s82G+%aI+78fk44sm%mIJDu"
    "*X4FFANryeg%W~q9Mc?2!dQ+vg93GnDTOLnk7=^3Tvy`c(Os4af%3iRjpomT`MOTtKq#x)vt?3n!L7{Gfsi_=-Yw-A2Dl;E8w=P1"
    "er`IuyVkK>8RR9H|N2FbZvhM$FQ8qhy)|89mKpH{3m3Ss6Y9c_OB}ngRrHTIs_LH=4lo$svm5{Sdbt1cZfkdyJwnuYnjD$yDj@*-"
    "U<uM%A~{vjO+bktBPLN9l)I@MU4;m@hq&Bye#gznV@+5T{G7;>ZYbO2)T)wcER_Xuf*P}_bdYATukaEPe*fx8Z`>Z}UMS+9{QlJf"
    "UfGs7v?fJ@If@#G=#px+GK<P9gR~s1ZKH^E{o2#zefk~Nv2hwEo<)%(zZ(Cu74uNafCB~8gzd!GSO=|M4Iba6Hdm6auV0?|7j6$0"
    "EZykpDVV^KP=@0$s*@ANg7yx82yCKF^}pnepwC@bE?pO8eBaff-rXKRQYDm?Rg^x!&UP_Dx{5G|`ra%%#u*YX9tH>ldt*|TW>%45"
    "Ggn4<EihBgU0!7*k$vbS{!xvWSYC*zB&?TGq8lh)DIS2e%+bc0CSAAr*QtMZdyqX&N1<qrlae!d8qUwdkqVUD+r<RcoK=XC@{~$X"
    "I^;~sz#uvsULJZgun$QM7`vh}0k}3O1c(CnZ*56^M*%u9X6IW<SS?+5DI>C~V9qsre*Vv=KkgqMZ@XQgt{|4V<wGjFQY;(`RFpUk"
    "Rht0EL$`oM)e@~K9R(N<6sT5n8gU$fGa<?M9|oNS2`LlYuny|QD7|4;g@xiU1#n$tMy;zwHw+G>RB{F@D?zecALfGpbL6Xy`)J_-"
    "w`CGxLRJbqK5%R?jac-Wo2uE0YHcx7%NEF@TH2i-&-=G8kL!n^_l1>BeqzETBNdNICYe%@E3Qc~w<Axn&x8X8pmG+LYFc7#usE+f"
    "rF?ZD#h~9`m{z3&OY1chUN2f$5EeTrVgd74D{v*@W>wyq#*tBNXKWJ42WY&AR+ax#*CH1K&Gqdo6ylf9y)1iBgubeX#w$G-Fybq7"
    "<&;Bh^C;|L?*Unp|LPv47WgkS>=(Qxp2s;~zvyKZRr2{z4C>vphqlyRs;YpoPmCBNbVU+TwQpU(VcTuDioyHy7_Zj`$Hmn}W}jq*"
    "Ra<MABTNcsLmjVk5xOfXn`VH_XE_&D6=p_P9+sCpZF(uBE`Rl&r=?a^BP)#`b;t8%spBGy88YNn3gMX<Y&;Af4`^56Aso7?82F|9"
    "w*0kw9%x*~;LipR+QWJPeYLQGo(wiW8G+I?0{gxv)kWj2GCMwaDK1-UJ{jy}dU)4Zd{^~jIug}(A4&V%DBzHkFjBJ<!yUF+C0h+#"
    "ft2GQ>sZ%M#`=K4v23dM-31O<V-;7&#w@Rr=GBf2&8|cXn{yEqmmmovv7!euSf`PGUFy919B5wH*{k?7>V~%~yHsN6QX_BhawgN1"
    "Rcvp&Wp^YR8Xlp3H0D*~{WQq8ua8e(9>3i`y@9WeSD%<MzN)d@ID?p#C7Gd=gU#oaGT<`j&CV?5gd>8;s%N*^X6EZ7T@dBjm(%7^"
    "<@wr9icJ<mrUH)QXK||G3D^r;BYRpWU_$seAkX-A-f*`sr&L4;CQ-F?#{el^RxP+VB~G~yQU@+jOh6{MLze+8&crjYPTD>7_E0Af"
    "ZY+c)_=G<TGo`vzwX%hf*jO$|MMdhWjLbId9y6%cOi@Rf9e>5Oz7F;5VlQ}-cfbjZ3*Qi+TGE23TeZbbEKl+84J7Vtk%Yx4-AjAF"
    "CbQ~{e%&1CR!JELNUiQBU=jyzZBnnH%+eV3uAUs&Da*kL4o5zwQBDo-&{X2?`k#;Y;TB99Dy;Qzs#sZhD>molkftt$TWpFOmC|fc"
    "nTD0T3-6I3*3P6D=FI`$-AviqnpI0~1Bb*%MCPkWktcYQ8<rjxAb|w@V0GdMy>{V$e6aOxpQrKl!su@O;~QB0!l!d0Z7DIrXj$np"
    "tp}+mqoNzEfYQ5|E?~9cl?I+NZO&d(hS%76+#c!5)s)*xLT9rV!P%;$&Itx$BWAU$OpKP)M5;)+o^7IgKIk<+2w`K^uMBp+HOdBu"
    "2Z;>Q$Z$}}YEw|^pwd_ZAXTB1CAupSj==`?QfjEhB&&{!r$OGf-uYY^rMb)ZfUU3^9zY}-q9wyz>#P~}0ce$-Zj1BtD2#DZxBwkr"
    "8S7T0AEI8xlz1fGA}&@V;tzwH>MjQ2gI}{o8LqqGp}IBMaJ4d=+86J$vG_F7FBhwPbJKc*BrE-#&uNnBjBJ(A!Lvq{$yjzac?A=J"
    "HTZd{NTiqOarsM;er))Ny8XnxLKPMCP}k)mIb3M<*7ev{KAG<FRU}lD|5v4*QcBvN5A`n6?>HQs!d(W_Z>0v7v2wui?ZNa5n#$fE"
    "f;APFuXf%uZl(~3BPY}UY^ZmUel`OX3^NKO8i&hhenvI8Jve-x>CimLOHr7uDp6em*_f0n{wH7cF47O$1GmCNapaP*gxdv0;IS0&"
    "x?&67A0u0ZBD@ridkZtDnG|Oq8vglE?;`yQslpzVb9KZ*H<Y4ymdhKZsVSn8@rX;o$!s`%bz>=ulFFex?X#h-Mf!`b_i@D8tZCE_"
    "d4SPzeqE*dNxy(G2lhyshXRNiSF$yikVuZ^3~GOc;6FMo!(TQ!`(q?^dcZQM8w`iYI^S{YipjA!HQOQzxK+SeI9)wOg&l8=1E77n"
    "<bm59scI$b9*~V#RHqRXI0Pb%0!;(puG*cAuIF9a@af2Vu*K`T^*qjhD9(Q|#Ql%<zkjYn!Qc(JMBCZWiX2M23z*l$E1U}QHd}5?"
    "#loeF;g{~RhWxu^LXQSY=KLM^|F~P?>6fgjDPce20cRfto9>k*8iXNqk-&lv!_pT3stU7Ik1Fj!j+z-9rPfY^{K`8Qq`b&8S@4+#"
    "dWh^;9SGdLi3;otOoKFjlzQHS&k`+fczHPU#yaGxTFe`Ryv>wRKZoVlbfuNn9OrLKf*jnvo2ss06CTEa`3br+Q$}W~Sb9}W=JQPb"
    "_}0E&=sCz%N#kER^9$p)0?eMtE>fwKd@P0r`^ow$7*Khg)y<qRbRYZ`X#aWCSV{)CmR+Ph9F@S{lie_Wi)Ur>hYG|Gu|)=&Q#FzU"
    "tZ$CMxhd!2e%^f@_j6r?3Rrs97j~+qOj!x4(&$J7yjKFyQo=&n6^XQ2wm8@XHlwOgoq%Eet+Cz?{XAsJR_1BaJGIm6HW6G`m6D%y"
    "O<)af9ptQyr^F(b4WqE64>_(3a4Q6!;CT2<(5}pW@2rEqND|m4ttrd}RKc{uRmLHYU#v?(LX^3fd2Qa#A#l#zg60pmR4-Uy-5y`6"
    "SY42cFUWq3P#orz(-gcI`_TU?R9Ig%!pgM}_{VgnjRA{Ym>LF`qnN)Eznqd4SDeK_!lJ5?Ang@<Ii+(e1jbLucAtj21{DLxLuMbE"
    "UDRa9sOp$gCy1~EKD)Ebs=f0aQ?~%!c~_OX*kO7&FAos$IcW0rB9dQxfaW=MF8~6La<l_(N{{Kv%Fkv3Kf=QP;(c26y#Ts&scdy_"
    "-K&wg5dnu`DAgk?lT4Qo66)jh`&5*{Ed>CzIno7nEpvh0)DdAS;^dq{%FmCl?<3%elZ;=EtRJV!4rW5_O;no&R*%6mfKm8<I^$eE"
    "N@aPh$J&?Iehc-lM8I`RS6q_lVo(bvj5?sdK>-4XMMb2}sfn&?PJn+^x(#J*z*)>H#J)Pzy9oH$Ajqy%?J`!hSWD$WG2AL^*=-i~"
    "(ri_inKh(Dsql^jNyd<X%$1LMO?CH7h?-M@@1&5oma6aBA{F{8vBWOfW4CbX>dykc#SMU0HmqM&054B|7XdF$oOpnuI9pzoJwa@#"
    "<}R6dUm9-~ooZ8hA1gK8W^BfWCE&<j&RD$}0r!$r;!O;j9zPmtNxEO~@P{b{tz_z913|A?3~+txO1_vuO(B?~)ANrz*}u1kukG&X"
    "T6!!LoQJg>I7z$bB9su>GyFzThMz8Kw_2Y_5l$&9OY0P>;Tv7JGTznrH#h*ltX*BJ6mFYxc%0H>b%nX2gbV<S;GA`o^Ed{p5@hVU"
    "*LlfluD9afS*7O6x7sSw*JZ2<Cm@#)EtT>ZxvUhJJlT{q_TEbOQU5<cz8~kuUkgibr*?T$Sw_0**vdFKoK76281+2cmOWt<)KG>U"
    "IHAEP0WKW9;P;hL{*z(p`g!I4k>?0~RN!PLb~DoijH?oRXC$~4Fa^vWqEt#|Rs#vlA7CE0`65G5|3bKU!nH={1Q=;0dPSF14=#G|"
    "S)7<8wFesEP^YHWw(7N|jD5EyqW;N1*TTj4SR7~oH8^0@hz9Ejj8xg|R?Q5kmp!)ANO(ZiXiK7LsZqjI3x)B?aOZHblto}63earG"
    "qon`3_tKZCO|=f#_X%rOy1TNIvc(Kkpx;sJ?A!WeuoL~CQy1AoW{{QGAxQS)XaW?r5$Y9nPPz^SWm?`POT(Xc8HM>MpN;havhw$*"
    "=(j44_t9Vu|0vagIHP2#aDA#}oJ#4I%6Jih$Wnz4Rbi{sNY}!}nbXv=+L0uQ<MDA7+m072QXtI`R>^5XtyDLk6^REAPNvzYGw6#n"
    "SiKd*1rg-2f@Jc_Zc;}9DPmXvqP-}sCrSfRf-Fk1$naP%^{iFY1a_x+di?Dm?iLyZCE#0OM65-CjY14D<u${68W0v}w_!)H2i(z)"
    "^AHXI&7{|WXZ<TdT&uDVkRALq4b^jku5e}ZaEBZxY>pz}yogbUcHQr`g^_jOwXlP`ITZHi+k}DdhHt(iR;PAw2IJ6_?5pOijU#*b"
    "O)-tWY*ULdQ;K?1u{kOz34g^R2Jk^|HwV5E)UAorxP~-CR9h9Wr7dPyr|~IE&uMG>*P`|zkOVa}8>%3j9h#0G`}6TW1a;d|q29Kj"
    "zUXrTUhz0~0>G_<&s%Rc3Y)~eq=u+Im#j3C%KFy6^PdiQQTxJ1tV6QuP0QyX1l5>P6uHIX!*;_V9HH=AS#wA;tajOv*8RM_U4G@W"
    "T^J|kerdO-v{lU91!0wgQrSUWm$eG}OZ6T=bZFSv<PwO|MQN(s90;&@|F^rZ|6bQ*4VC6BZL=hyH5~j%)9Q{`xu0t&yH@3eoJr_F"
    "ZCXFoA47!j4){)cd(_M5xH_MMf^fpATJ;X7QBg<MZcaWY=uTBSNs=~^XJgSMM2U-W1~Zm!j&i}Po)5(v^<8R3Cp~N2#I9+3H9Cz_"
    "atjzgW7V7$G8F*9^4Xv$$(nh8q|?Uv$&j~LmZWAR?QEkmKd`}W04b*Af`{UK68sn$-oI)nu#0Hbh7C&!{R{3Tt+xJ!JAffYjGSj2"
    "RT50tf6U18s;^V9r~~)GBdbLvs7;fL0{E(G!Ys3S_wAA1?+!p^8!8HPI50qxavVT;Va(i>w&if%3c^ch`l!8Dc~d(MK9jlTm2qAw"
    "Q@*|>Td2BB7tdZw-rzEI(X8GpWi}iQ7d9wYrQ{~<felScyoA!&Dixn{bCAnB2K7;lYR#&-NdsRsbUY1AS{lvONQY>sJ1@jQWshoh"
    "ITYAsr_X%G8P|1Fu(T|Hvo5IsRS}leRpbjx2|?~ANykA~cikR}M2qtv8ELDYg!$|yKe@^PCKs#gZ`adyNh&O@<j~+cW%3<Hba=6u"
    "anC(gAt`BRNI_tRHLrZq&7uXVI87DAB%pDgP<9Wy2wQd6+GbYK>=~LGX1WG#a|OE(W*bxaQRk69yUIwqQqslmENW56gsI15SNH7="
    "42CGouKTTWq%`OzOeKS`&?QN=E4KaiRfewSvSZ0P_o0CU;U8?kiF4-6K%l!?GGaZ9kMJ8ceqv=4Z~$l!Um9E1zjBoUzn0dXi>C4J"
    "d4t>~*X-0o2fnC!d|lx*h5A%T(G)YuIZ67vy{fm@zjBqK`Z4JWN4U4H_JPtB?vF82+W`rEu^-fwL|ypcC0%#Tf+>=5FvEX7)Vr$;"
    "^%2{=-3-bC#Tj#M8=Rj#Fp_gB%a@K`@FSHWV3?S=4HYUZm|N!aq266(NGgKkC1F*yMv$Q^P<b&)DX%fDU9}ASnN{UL1W{JARo4Pt"
    "u2&e)=T{kCviDmm^&D20ly#$WM&+3u3`9C1Y>`8>VM*&ROz2No9xfqOg7a|KuNdUI6~8P-3A7s`xtO`8%<7e~SM{hK=u+BeXEL+9"
    "r=sgTX(XDGZjJL1UL@1&Is*O$^1ktbQ}$df2k;$sGG8Srg`gW%0RcjK4N`lrN))SCzUM!5mGN$fyDxt{J^i>ec?w<WngI+8ScP4?"
    "q$Y$?6M(|SQWR`rX?W!o0K8kNMrJDwC!7t@%Vo*^-Fp@sReu6!H!HSe_Hk?#WsDi`!AdDn7H6ueOb_%dqD6fc^&hS{t}`sUnb8Q|"
    "ma9mB0r&=vN9pJIJQojXv@R`Fm{!SZY0Ed^zOfuwN3+$C@r*A&CiFW_!HO7{BY>@rpb@hmF(<E1lbEv9ChQLS2>h>*Ms^-pNV3u?"
    "ofqZD*DnWJ__o^LFQeJ&NQRRE`gr9!t1p?+HB#74f&b+sLKX7SQvz;ss8lI(KgwFU$7|!f3+LeWQ>?bBZTu3QP}`3z>G&{IzR0P>"
    "_V5EXLw<Dq=q2$QIi6OzZs!5s-OO;TyjR;Kycq8YtsN8a>+o~HL_t-PyaOi!L<EA%;;5>*80Qs>c19sT9@aj}5{@eVE696eY86!h"
    "@^2lDLtBPJf;FCgVNDF~Ng68?9*LjBz`{!<N6hxO`O1LL1v2gKYRwYonB%N)gv}M&Wp-)NTijU!EvN;Pgc*V^yt*p0rJXLJWK5@1"
    "rRQn97a^sKWRWdp6U7D;!^lR(7HW5vSM_S$3pUDI8Ne|5VW0z;w9!X5%rJ|0WrWw7m^1u2DzvMrIwX+7-qtRdYPn?uyMnS)R^dOG"
    "nBy`}v5Q0F)E~vupN;lz;|(?(XRfkK6#|Xylf1iBfR?INGK79^s5HlaurS>mVnA)cJzb3Le1bl|v%?CsUW7L$Hcag<;bwx<Q`z@x"
    "Fny+|gaF^Bo9LayWV{-h0Q#?lLVn&&cB1Y&KExC=X9Hu*=Op#$6>HtVHx5$Bko7TCse&b)Y{;Mt$E9Gx3d^n|gZRow&$ojzLGP}g"
    "gxMz;4I63=R2k$pv@99kK6P`dg3hW^i=bo=Ns8&7vL~avymWJ*E7wqblxGiusi2sP!;BT%Iz~fT4nT#Y4R^<E<RwW<cp=be`r)H4"
    "bn>mSE?PnBCP8gc%2B)2OY^$H%Q1EJ4APyDQahmT>gFqA848e#UsiRDzB0f~W&F$|+>FA2I~<D69{Mer8%!rGLj_cF*MM{Etb`Ci"
    ">KNUu_6liV8R~ousg`0=brCHENO@aou~y3BP*b=C@E0@C-BIpgt-AVpXeYLEfbUkhGRO--zG8(2hcBuzM$|niq)#nncEmRfTNpvx"
    "Ov-ZV{&q+LsBCwM`l-i5KkvCKTfp=_({fgqNS?Qk4bqRVoQhUMDzF>sc-Vj`O0EWD0~|q*lf_d^{yfIRy=ulU%geeBf>+BZUH?p("
    "0n-dn#Hf7E7XW?<5Isr%D5-5Lx&Qg12;|n!!1wBHC%(n(D9LX4-GFE*U(m@MM>fPzb(vD?jYQWldRvtaGcMqv>XFNNZH}U%e|()!"
    "e|%v2O_G-#Y>v^cb00UdLk+5|bZsH7Zs3&^1?8)^`WPr@DCdpoS@jJj+_+Z_ZX{ma2T;>y3p0JG<0I5-1u_?oOC*fW#E1B?o32(B"
    "OyM`wqv_c-So2<&3}mDd>=6@;UXoo_4Y7`PU?B2-AO$7_*fvFvb5~*^oZD&SUp<U@=3ls1<w$gO<91-OFw0aAWZr5=iCstx2~&`C"
    "7Y#s218URMhDY~v5m>eMd8pTlqSYnQkFnQ<b5T%3Rn~`!I<|L8I&o!1-`rj!H-i;k5;5Xnu%qM4li%HXs^W2J{<^N(mx=>fB`I1q"
    "slOeX{qW6D)jT0_?yT}dA!rB0_ysL^=;f{F{WmO=cId@nR{dF2OC7b8+zLJjbgcnn_iAoB?buOrt}LM%&}Vhys%k&K$H+CF#~Ft*"
    "<M;OPKR<t5bkZ3^+Ct35QfVp#KuWt!DjA`ui=OoS+pMgGfgU<9F%~AtOBbZH^DuYq+rR#ODa})rgK|`7n?t)dN;pwsKuXEOK&p8?"
    "R<{KUNduefA`}2)Tit5+bspj2%i|O1XngthwLi3rIfH^bIf^9REsxQI!ETjBNbg+TRVALIq(i75a3ZLWn3Nnb@J`i<r=dFk^7ySi"
    "{_$aPY*FU8>s^UAfFLQ{hsHL>XtUhPWdfA#=C-Yw^8yst{ky8Oz1lCF2fF|M!YaSauMd~xa`mbEilRnqSye`RCXunw4>3;lB?C>U"
    "KN-`@QLzvg39otWH|F>}*2De(th+Biv={!yEdFSZkJ=fJKR2NIBH{|%W0ll<i0Ai117@>2v!*Q}OG${uxq})JXXQOPP*Rvm9Apy4"
    "wQ--mef{#^7u5?2I;y*Ug28ss!;}`_cC$1kR^quh_cHuSD{wU$SB@SFSUaV8Tp8l0?r!?myUSgnh(Fw}=?XR05+z|#^>w>J*s<|L"
    "n)Yph^RRURKUJkZv)l23ZwBVWC@=TobB+58AKVx3EY^?RRT9#M{3W>A2A~BX#HefzNhE@tER;yv=6u*rijU1(pL7huwtoQnJzj|a"
    "NfiXDu|TIzik;R=M#CDI7Cu+fx?A1EDo7)E4xp(LeiUNFOWgXh_4mslN(2l|CF`q2wq{4kIMR@CDX+NHAi!>ns!<;ClwfG)qb=`Z"
    "6q&s_$UiS|`4m_%D=V(4%MiGW3aPsH_(5GlLOUU~EyNXz<kBpg!l`u)C?WpJ1wD`P^w93WNZQ;V_QbTts|RCDWkpbC!JSFKBE#LC"
    "x}{)EEw)wCIG|9anoF?A;+^nuzmlKd4|q4f;hHaYck5Gp9BK`NnW`>RHCyZU2&`gYGcHVmp=y{tp-xgp8(l$B7VcL8)w?nN{q=|Y"
    "b!eadd08I;9aJFNvD1wd>zibIC2A>ceC=uJDIaZDaGgP^KQ#b=TZ$@wJPkBjKVoS@8xI$E;h>@zdxug~(PU<D=%PiLl!9!MoWMUx"
    "j#1eLTb<AxRNiyk!msYM?}vF@Ux3W*ZO&BI>ZR`4Rkw|2(ESnIlFgf^lU(PNoG&krPaMFiz_dZIBc@+E73VSbwNJqr18gLQ-=nI@"
    "wa7_Ix?P>5R05(PIQSVv;z5NLCnmPYmrh*ddA}Wu>GA&O!%!Q*r}c2zJVC*(4lLu4^Tsf~7!SOeVA3wy#xC@_t{uF`aLK8?hUN2|"
    "qI}7HI@rSkJzU0$S}f|}9hDp9)DsWy>Org=$OF_hqXbVW4X94uDB>ykhpo;EO7Q%2G|`U_<Eebas*+vEOd`Tqn`l&VR=`__6fEo_"
    "s0cFZQX@)<)NBoz=Sv6b_v3y4t}qMk@W*<12ic)rb}F6I%j~E)LS;U3cnXuNhs_YX<{jXVyR0Q~oSE@1oI8x~)v>-lefc2YGGtM)"
    "Gd#A!&~O3jVy!TTj2nbA7`1{49zM@TQjnw>opQ(y*kfEB=Kk)|HmGGSI3;U!l<|ra*G5wsn=_WdJ1dp2vx<X)oZ?m~vx<*!nc4Vj"
    "L;UzE1Ei_DXfgEWD-`)q!saNVN^?whbam=$xm5|LYYdDOxQPP{a1K=`S)N&(#hKe9{`ccK^4e8~!4$@liW{Q1YHkLAP)P|4OR363"
    "CB8~QtP++g5?*2*D+Y3<+oS#X_Ve*_CUec4VKHcBc*fv4#`q%@ctBI+z+3W?a=<{SN>w*9LQ6Adn7O}VmF}6n@9W{$o_|}iDrwcN"
    "G-S;cM#6eiqdMNInMFw!@1!;aSU(j}vG+D4Pf|-}x81G{q}z&jAEPUrX_Vp1v5^K!)$Ro!OR&tSg$J~5s$a-dB#~oP1~@qi;IO(^"
    "#`q7W)x8_&=i?I?_NhJmZ9Vai$G3RDGQ2RKOTD6$ZmOeVSdI*2=5TSw%1UZvF14qoLL>zj@MB%^qjk0ruUAU)>pw3O6WG?eRj%X6"
    "Z_>q%^q`qCTnR2iWoWvylfE$X=b2=+L$bIWCsiMJV<=^J{M2{-^70n|Y|2?-;kuHu<mqZ030|$KYra63411$lMbnqM96?>Pu2|up"
    "t^V0~?}PN%p}D01yVc-Yp_Tw5a-Q)q4=@rJ)Tt^g^#}xAcnMGN0uqS;VVwuNfBN8lF=S;-)~JcND2&J_U>7=$QKeK}-LR*m80t7`"
    "O#`?kEDNHn*yHmapATB3_vFb4R`1c(AIV|sj+R@{Z##Y9_flk<jts~Qn;k$fxff$Naym`n3|FqCbYir?3VeIRf+kgtFBu(m<6S<A"
    "J{S283Bz`nwBu*t%rSaX;7rY49pi<djrQ%^JMCE(q6Ai6LP#ogTWa5@irdwJdGhE!gd?v~_}}yVmBnwz0v*<?V?F-tk8FS!lJUQP"
    "-Yd!T{lH2<X%o*5&K#hixUp$*G>M#Kh0B|+zQs&42y<@%S<%m>bkiBbUmy7X@7Tjb&f()b7{xV|*%Xp87T`Jo;yEBBQN7XFDnqw@"
    "&a1L|XQ_QG%eKM*r|^=y`0gEUr+u>jlpK#C47g@sn-nU2VkW~DcgjP(^V|_0QrsK3rC%u^(qQTPld-NuQ*ru(9icqCm0U~8ogNk3"
    "jxEIWHt?g0uNs?4veRlbWBKOhF_&r1^~q@9_z!0S&*(x{6nHRAeXEB|0G}%3Lx7RBGvY{IY9%FG)%GmKnzq95SArz(Q$P(n5L%ND"
    "E2LCOke7PbY@Ie;Uv^hhpHnx6QN318g-E2<lzhhvoF2d1|Ew?b+eLB?T(GK>o0=mSIlOhWmFK`syga}O+XyScUgfY-hx$I}%kDXK"
    "cXl4(S4!A3lY5u()+Bwo>XGV$L7!{lCKAl42aDxbzk8=1ihw^@-k~zhNpW2b6>Avr=2))@K_9cv=20nz*T+7nI+xj>-j|6l#9s1C"
    "1rU8NwqXU;{}E27HUZ2r)F<zoBfeK)4*sBMOjA+GQczo6=b24B1|Z4;1@Xob#MNaFh`VJ;%mQ|ex;LFh`I|P{B_oBHgGyFf(>RR;"
    "Op~fUc5%2iz0I<Iq4Fu4Q;kcO)R`&TBHdo`#D6?}|Mq3xkE2D(t9iT{7%{%s-b2RNZ>NGB=Ym?UOX-QvjT1%*EwMl*D-|6qB=||~"
    "9Ylw``+V%j@u1l9n>x4a5qAr;7^+cQNvguCl1-`^$NJzo;X%EE9aRXln-eT$!{TLHzCPIB@4wEEBkgDPJD>%YU1i}`tw;PSabX;?"
    "ZWBQye6eBItBAIHb=b@~PThr{_u|*@0`5%WPZg;=JzL$&WZ(%!99_z?OW>)=u68~&wxtdj;E__cZaHx}V&=-KRn=Kh3ghR)y_xxo"
    ")&lGYP-#s`k?y<~Zl#vmi)?(Ga$!<fRtB%Fr5RQGu*a10S!YT&2mIH#X!1N~cFrg+)mA!avGvMa!7@RGb+I9FN2q@pVztu(A(zB8"
    "rkI|)Ig4}sc>3c!i)M|j4;m7Ff$pybr92e0pbipA0qc)yQ)#$Z*sMhKyoe;6N&QSdAMVO5D(4)mDUzoIOlDIxLpZP;D^NjB%}OZT"
    "E?qvT(VYVD_|P!;{^o8C_$%|}LWtbeES;<x)PLhpScZT}n_A_RTVnA^k>n*Iq9EOMCEf6Dtm3>qkH5J1Wle!ofnFaf-HU3AnCH=d"
    "+oT}p?lCQ#<{tJ|c^KQ@s|#!JhX9DbxetHwhhJHy7lNnoc#ObO_l!PWm-vtw@Cb8MqQi`EBT!bgP)VwEk>Ebli_d04;-3t6*^+nN"
    "jr(^O>|GT!k_%AAScH~UxWq8Jq_$C6(4bQ$K$?Cl01|qWOdgoHX6Z(jTVwwNzc$*#MdSt$jG+RWEl##_ex<XEDa2Si?2DT8sdGCn"
    "Dyb@OG(dUv7QofPJhzUTs=N<~bAKruw2GL)(0x)ZQMrmnnpv%>(_mn3aRs_4R_0YWioo$sBTKT&&b`O&!S3MCPwj5<X<wf2oG!w="
    "RrPLFKvkJCy8F(!|5b!|s@+f*G3-1JP4=p;%g=yFeap+dJ?PITpv=3VXp`g!Qxw%N)Fjxgg5o%rJa7metJ&4qH%h>5kJ+LU*A)j;"
    "v&XvPr(=~by0Ez%4$Eh)Izz8=D017?WJiGE66AYsL^M1+-3UE4+$#pIsQ>zb(67wrowCxuNOcZaf<^h;!~Mm*UD?4XWE6+u<0Jbb"
    "J&2*?<OSW;Ion}CemL?hb!RrDDFUZ2DuTW_-aF>bDGofVhK^C1*vkIgrA;D8AbVw1Rsf1U>RZRkSru}8Z&pmZ`FdrLD+)E^xZ7&g"
    "E!El;FIhulM{~(yaJA#2#Dta75<tkzpOgcYpx?*5a?kYNk8f9L?;(h^euLzys;b1)2BL6Ir<AO)V%RgRq_iiR<K#v4Ma493uO!7<"
    "ulTa>ZTxZn#k<Qat*KTtvme>n1xl>$H>Kk2s{@F_VA*OMGU>%z=1YAe`!Kt}plrA?!fu!QItUm_HX2MJ6{`k<QaGRagMNa)u}>Bd"
    "50S@is<H|Y3LLiH;2*9Gq5A|mtp{Am<8|#3ubO-_c!pXS!})@mHJT&Zq4touNT^t$S!<LyT8A2C&*&St^h)UeEyMpA-@n@sL4{3_"
    "_p0Zcsp^0HZ^dPIHkKLQnvx<&TWRZIbg3sxuBKU2hjpI}#=iLbx;t_N-V9;F-g#KLQOA?OMpk<!26ath({S06r|f#kTN3C30jkB5"
    "lzMRWlhGdk^}XMJyQr@(a#SO1^#D+3;{{@q@RK}>^7c9mJ@t^%!Yp>_$FctsgRB+im7Cn}?T&v+#iPFsBKhxNl%<Z159~;msOE_e"
    "g8(|;B`l@F`mF;k{3uFh&2#5RdyXuBzn?$9txFo=y|UIkAZ<O1NvlhdnnHUQ)fO)nBRTk@PS8<#<VD3mE2=NaRsQw;@#U8DDqO3;"
    "7_X9u0Bo<@?1(KlN?b@*y&Ul-x|YFXrry;&a*OSGNrba`uEZGLk9P&HB~>hL$ptLSIaUv!s9SbSo>E7AQf@B<Pr{o`OVm1cYO4MB"
    "<`}x0Bi`NXh@HOBOBM#-GbF6gi*m!$(KEL&(Nzu!Q~_EWAb=Hu+9zkTHTg}stn*LCyYhuFO`H(h&6PDK;Ff;`?G{$i$~OVLfsB|y"
    "iTtZX6jY^50F2Ej$=)1MxmKs|147~VW9({Ir(TO*Z5Q)VL%3B)tBXkW6>?RDT>(6<rhx{+t)9p0)6uSc9nL3&P%0xG{dlkt*dg`n"
    "mHZ)WIbwSyLZT*~4AzqJkJWoJYfGIkJC357U)=A@!(zn8i!iWyHe%?u8j<0yV3RNzBl)BX&y%o;g0aQmZIn50wQ6|=Y4|AXzI;C1"
    "<A;l!stQb#lmMAp6@Chm&FUZ|@yb3Ur=Ud`jZm??^W^v#ku*R3=Yw4UM8i@8wy`95Nf^>TWQQd)Ek&@ooK%?AzBL71NlA`^vk(-I"
    "Xl2^#!`!Y*!t1g^ynGl<<_^1Ij@EA`di4k$SQl)WuF<7@nhj@sNFv(sjpqfsd%hk3)BODB#jTr#<~6U{&Wdp_hujUW%qnjmuB4Z@"
    ">*y0CxsRoE<Ccv2YQ(zStx@pO_ir<onyz;N<(wjXvE#3=p$?czzW@&i#yC-0Q%Y9`+j7zgnRaIdvD&Rs{&AU64{=l%u(pf(V8}Uj"
    "{IX=^Riy!18Q65m93^E@6;(zC2c(aft`yF$<V6hZ!#z>9l56hLo^Tl(>m?=IhJqM*JI<&H(o|vLl)?hiz{jz<*`DK28of2n#6%px"
    "<6^%><&|;#GM=P~=smY~#OA3zm{dNKsuGnk2BpIfv!Pp!f+2R5TO<8<d-yOC2(V>waFCI1VT@_Qf$F$fB^uu&Cs~5(4ZNG%&PsR-"
    "fG5KaH0I_=$MZjoHPm%QYGq;7Y3**hrQyshkB5SqW|%mrLLE(%8R`_nR-P+=AQUohjdfL!suy-?s}Qx8Bset`48Z0xjad>9_~np;"
    "X3{y1s_oJXpGy5>!|$8l^@}9GOV|l8&no@EW~=%c1o7jT*G>-RrVhdf-B$`PJI1T&`~c1YLm=cWT=}m1FGr%mr4qx_9~a|!H7N(F"
    "04L0fN8YBiXX27*6xh(kB5iCVSw9X0M<cE6ZB#CGx;@^x(n`7%wqr-x;km(h3P4Q)YuG!m<}zwD=u%7=tBgGa+FP?#4?Uy?lWz|7"
    "^w8utE;2*BRqNnh96m5u=SIara?+$XBe|ufY8aTk&rmO=2nW2Gq8dO^*Sonk)Q7K8KpBLRd2m-Mm=t;>S80?Z+Lb4yWKU)&?jt{z"
    "Q>%`~!B|1K(60<}_xw5S@o`-$5$9!8rVmu<MVbW*listz3>gKik1Op^%c1kEmUNQAlCFQ%6<{bg271l~5i9+2krZ-SK++d*MOb30"
    "@$;}iFg1f%MjbTpzfp%4V`*Hj*!t`Wo=O1NDfn=0*w^sIYelsf|GQBARvt@J@8ngpL=hY~Q}l9dDJND*5h+<0(`nQL$Vi!1V&}Y("
    "n^#!a<*<i?JYlFJkwmqtYDsWPhPfV+oB(516o%Gz!uzvZ5=+g9ar0gr!;Z%^`Ok;E0;C+gIO{4HzXBys9SRF|@F_u>7g$k>ab4P5"
    "l6)O%KxVL%1vm%ZzXB642Yn9O{NwA>ANN0>6j8Y-7~3FjJXwY>NbD4s3DJ;lcE{Z{4*L+O0)g08akh|WBL(HA#Dy!Vb9X<!U+7(Y"
    "xW%{bXbkBg;n8pP4pF;f&k+aCn4WxGM^jBXJ|}err^GR3bn<(grt@gW8N6{3g13ZRfZ+^SpseGrV<zSDO8t4L#6QT&HO@%hNoopU"
    "W@enV1qYqk%&$7j{_Xya1;*xc;T@OC3^*7=4eB5&QL8m|QGwe7+Xp2yc?CUS@EGuo?^vn2TZ4S?ZjSA5G5pxRhIQtN$`&z=$MDf3"
    "g{lmkrc9p{mV)iDLMw?aY;!#yzL!+w4@v65d-V_oF69mh8?IH=Mprgr%X1_S7>}(zC8NUc!Z~Q{63nrhqL}k`_%ZtjJuA!>ghWk8"
    "*al5~2f&|GbU>1^Hch_4msG&>lC#1CsD*`;2d3oC&LeP?jw{|PWN#lWL1VQe75SC6)ToW8g6k#!;8j{v6!z)@J$P$a5UaN~2mT8F"
    "cpK}=2@V0G$j<5<Nu{{xDp(p&T?9xSDm&-fNLdJ`0JvMwJkWhs<0kh~6!dPiueTB*vV^H?9lC&6Y9DH)96C9@09%|hV<*WF@dsO4"
    "0771zT&$T2((-v{zgYV(`{&(IKuW2c^Xt3Nlx|*YNdx<o)dE|M2|(UfcO6*hq5`NY3{)$YBT0m3Tc-vS&a1=3Ul?>fj`rhHAOz0k"
    "`jlqVl3J>f#{{QFEgb}pQw!$K(i+-T*Ml%MFmW1A#lq$<jQI61l9ys3E1Ra<2Y88k#PMm8VjY|$ue^Ju|1Y1^n3oMyKuC~J6$9|u"
    "&BVVlwO^ms_bc<;oVJgmV>vhWYnSd@QYp3WAE6R;m_60gqt%0q>ADq5;Kq~?_xKAVKjX{`MT`V&bVX8E;4PJf0ERJ^-YyIyn;75P"
    "2k%iJX0TBhJ%&2XtY){@&f;mr6O6D;PIFlBaFF7KY8a)qsJ;OB_QZ-GwPsC{POPrlR5%x_8b!93*0-OJ`KuK1B7$#qCom&?U7gI7"
    "vKkeRGkhWMa^%ti=P_)Od@NXTz+6zt0_bY|g>7`9x1b)RJ4@IL$ZXS6OE9d@ahDSuF1`dKamXI(5q=5kUc!$Y(#&T&{m>r5OZCWQ"
    "e-a5>t4PE^u%uWa%~BP4sC`$IG>4Ds%{rXg7Y1w$SV3RpeO8-^YvaV1aps$MQ}6oeIem_$ky4!kggR^sw36ACQe~8vjVj4MLUKiI"
    "P-+&UxKe}lz&ZZDZd@A-z=1mKswGYLz&;>fR%I>x!zK88?Y7IMs^othO>3j18q}~z-B7NKc66H`&lvi9zs&K&<|j}}h^1mQtQ`Zt"
    "phl9RS*Nn`rU=PUS9L|l3)2ZX2etr|wqKu&bx_9l>5>>R2V5#yu>>}U+Q$s9;HpzXvh*EwSEriprqpB3I>2G7C!aKK^X<`I@{lin"
    "<LUk~7GAN)iib}xYV33)j)NNjxb1XB9;~$DqZCxT6rOM$1s{wbGYT>9D?`84v%l979T?AnBh5w1LwiGfrUjy>jGu-47y~zjz(M!{"
    "GD-`O=;j#eX$Q)+pAL0*YL(iZhva*eqN*@{8TLYhg?D-Sy0Mj0nOL@i94xfE^*q$y(X!B^TnPqV40lk;ccTI3pjm)m_4+AbtdP{_"
    "if5@OG>}Qrz@`S1zKD~IDk1-=E?<4`D`4W`=iSrS?}A{*-NM^I%WNaTF9=6Isscd~+U}T%TGcsyL92|a!<fJ&XEeGbo>dfFu9N{i"
    ">I(H82vav6*jzRyRcXp&nwEOXKtJ;ADywX4!OWh;9(OhmUzVhwVkam53Nn8DRaSSp^WiUg_CPF{CH}tp;i<p_NOp9zRNqfLn=|SH"
    "!;XOOWE}?B7j}7`F9Lr>YPH2LLKYmHq04(1*p@ok#zKv#I2vBGFO>o*bGJp1W&tO&2h{V!4^_{fjqaoBvXs$vHoUno)RM5AikB7$"
    "Ada=w?;c#<Bs`?6rYcQ}E_EzjXGjQ<f5m0GD<AX+uW<Lbcccs>m$sBq)T1c-g#mz3tHX7G(y*b1WZu;LETls(VmtQw%IfwI07N$j"
    "S^s=mcaJ!%Z|m_Qj9L%*L;xdCuBv?00aXT)k)R6ZHY{ak9(Lpa?<uGOTUI~aawVMgGTisCbAP=^K5{EczR^frS>brFISe33ai{@7"
    "_*M+RTV8Ul#`y#UUuH;&C2Zx`oCmu5`s2sCLgCdG0vD)rr}Ad6?iaYn0DP(oG@2Pa%j8R`L><2H%uZjgT*9lL^lPLmxW8<6wUWNV"
    "8gb${wwFeq*$RMk^~;4i8vt{WG#o&rtCu9;UEO?AJ_mk&-DbX3IbBHl^sHpIQ~@-23e34mt5srAmAI&2BS?y;^NmYA-jyOynOFAY"
    "+%KI2E(d#R4_C^zyp>s9>e~d`&MLxDc7WV(Rcp?v0!!o6g0@RC2P>Wd0+sEfjE{X~n8*M5<Ni@sI=}qX+mV7hY!=vS8K7v{PZbI@"
    "sZ*ukv)dL!VcClw`muG$p)<^InGW-E<&)Uv&%J@)CC*l*1e#If5hROJtv}k;Pi;k|cNW)ynOH^aRa4Wj1h?n>`k}(U^X_|Rgg_tw"
    "1L^szz6|dgJk(1%3S+C}%Wng(UTcd^vw&(pT-Cl_iM;cQ5qi3RYF94!0!)|>-*TVJnjy7KVXv&GtE?$W=@?{IRWIB(?{XA-DsQsn"
    "D{-RdajxuZWAnl}E4vHy!lnlKW7_~rW8>f04JwIIn;!lLBjq_=60uQ}BLLu)kzT^GA5yYw@nTVMt)aF*_=6}|u2NXAn3O~h*<>{h"
    "5J^xUr>wS288_Zoz|%l4S|sm>2_0B0?XEU-DP*(ETs`zG5ABI4WyMy8lYsj0fcPT-2A`f;y}WJ?!vY?d;k>nHcUd{gYY7q^qE*Rb"
    "@nXbPV-1-s31h(`Lr_?NQ)KdN67q2BDtTqdxBR(Z)x96H=xmAb{LTZb1)BH?Gp?ltY-*Npsj4S9sO;B0RSCv{*phfvQhjMxXymn="
    "y<35arer~&RnGWetN4bRcbaOHfMfgEg`<u0PjE;nN4jt%!FeSC;F{B?ga4Z6H(Mz2-HJtomuB1^h(V1=R3qpmmDAP6Lz*AKZ6%uF"
    "ou!&Bq1Z9!m2&gT!G2|FJ^l;R_;#<UKB|5lbczp?z>yT(m^;pe+8-GOXshr&2M*)|@~i4=Rsji&dZv=kX6hp4Lx7~JhovM408hP3"
    "ahrwQaWC+u67H?i!4l+eDCiFF!ukglzej&&3eU0MzU~gm<zK~pZ@wSfvDo_3z2vYTLSW5^ikFaZWud}#rV0)?<FS~di2<xxacB5!"
    "`+T@x7cy@jhtKn!)z{^@aG~0M2PLA-R<!<RaSYUfRTm0F@(NHs6%MO=;J7uKs%cJNw&B)UdILxLPY1g9By*k_#Kq}^Nnx;_?YO{<"
    "Ds4_MW$AUQ7q9(ftdF173U*dkV=RA_#Oz_Pay=SH?KGrBq~5VAYqmo5UZpHnB7?fjoi~PhuCzLT87A53wRO>m-^?4PW~KGdiXAN^"
    "oxo{ULUZApw+k3dYjq0=!Mjom_inh4A2-daYComq?W&fjlJ6>MsqLi`#0Byi09t4F8&jnwDRJ&_<T2#3u8-E&%`GXXDCZ)M%EV#`"
    ")xEPs%t-TUTdbVbs_r7YDj*@|p!j`PE7pGHe)_|JA3xAZKm@9d&zb6+xN$(DEI}s=K7y?hb#X`4GoLB(U5u#bm||tFR0toJSg(0O"
    "C&|3Qmd7laqwsFTEP;J>-&AE`K7#8_Wt3Cbu4=5z4CoRhK$6t6=ZqKs(H_5F+__71c(=9T@)#uy$nfKk4aWi|{EaPnVnvjlpf=^0"
    "-)0h9zUl7s>`ayT^Z4{H7{eb+m(zdZ0fe5FNFVdjXF<B3upea;s5(hSfx1S3o~Kz4A_22eD`gO^)JFWDjeld<v{KBV54G@67Y=O="
    "r*2oZdll(Lz)@1pgHwWjFLS0tqh=^Nk9j^1`|m5^ur3K8_IP2Bs)xMP4<%2e3vdTY-iP;VR_T~fc6@l^j1*>G;qi73yZ!qSbMidS"
    "_x9r=@GZ600o4Y)2~4_<;Z$20u^EMlb+O=9QALl)tlYa(<WJd-Zwcx*bga~@0(S&$;Dl<4d{xgu<rM-&1G}!nPZ$Ze&7mF!THZJh"
    "(i~T+6OTVyr~TK{KcAkvHsXLe5Uwgc*{cs1fU_!$ENkc`2rp4~7>e$3y&^ygKIz7@9WtZ8Cgj%xN92nv)9E0cg}tPr2`9;JwF0eb"
    "_$MW|D(nmVR9_FgGFE|^z{<+N{rGC^JDn}b-R<7<%uW3(Rczn!+Nr8N^fE`&J1Mzsz0t;3K&@dTY~PB3Jv4rgXZ{79EvQ)0?O1ei"
    "sP<j&n6&93e&9P@cP?RN?7tXxsX#&u<u<Fpz+*iR_3~u3&Q^<SUz<ElQM#w<qID&2)l*XCP(B8%Z<MH5;rH33eCTl`*UOXN>1;6-"
    "pp-m<!71(rTm*+Er~cWT7e>jeR}NI?{p`f_w>p%`y>Kg`9g@VyL(e)}?-EOV!4Wmd4&(j8%u|KUy7)8dJt%B3SxC0mfIyT6Bm|cq"
    "AvGw>F6Uw1B%|JqlcG7Anp>x<Hg*k@4DAY#V^t<PH8_IBs=KJ_BH7#EV727Izx8#X!jI$3R|%&JA!4O~Lw$^56+MGa43h+vY|K7q"
    "3S{b)GB8Y(Xw@NEY!%B>p?6(ZM|oV&7Z^{iUqnszWGCWphcZn1kWP;DGNnJ+<T&;O-520Y%`jDdv*mq+i85@tZF?H(iW&@ubt}fW"
    "VpBJ|37V;@G*ZJor!Kr%5FQX)r({QWUQWefmK`He*Yo0xZ(qN>D6v1{b=%X=2Tsi2-)f921TK3?G0Fv5m7pa>#et*vT2B4mhtQpy"
    "%}bgN_{p!LvLAswNA}NoNYU8Gqe;Z;pchL9t&djinwMk)q;i+L+mZ=@mQAVOcwg17Wr>o42-)SKLdyU&!(AQl>Hhx9<M(zEW*Ey?"
    "J^}bLR1A*)4Z@v#k$P*Z!LXM?C=kL*T?roQi`fPaqhf{wPJ9^VdU8WjS9siu#|a(HR=O%9gJkSMz3aGefFv)q5$*6;xsRd{MOKA>"
    "zc$Q|hxPdQOWpf@JZOQ0_S|b{H3wI1i2N)>zbE;Ultw!`3W~=`vvUlUC`4UkrpRWxGTO6T#=pP*xM(!vtYinvkjy0X{3ub9a<F=&"
    "sM~~^D8#^ic)kx*0(dNHIpj0*d>Uk~Z|(W!;Jh2u!(!o{RV*^q55THfLX%{0#un(dU=Il|U{RI4-8g?%-G8GlYHa>wFlZ#hT_D;Z"
    "t#gUM)`5ZbG8=Pb)<>t*D-RJzWYis9jbBXK3J`(?LBJ}lTQ|n~Fp4Sxr*z4ZPL3LMOqSj?FbTieFcJW3*8%2gm%?sq#!UrXhhz<7"
    "Jdbixt=I~fdmE-x*)q6+2?C7_V<n6n_g(>XTP2~*e!#OStf&5rpiz|&o`*P8E8f{}3_?~<tFa{;0pFC?i#yhx?F2Fj((=i8Jtw(e"
    "*kqe*&U(~;wW9{%!x&E&`Qxe`=QVrER#q7k79{16l-Xb<Hz~R3p!`W`J?9L4Q%@+kqyr(Gox@ue<@;b0=iY(PBC9HqF|`|1{H%8M"
    "h)qzjt)85CA89K?<>8C$Xf0vF6|eJNer{*=xc>I8#hnx=!1F5chvk6)9f(Cy@71ypDDI*vxv|f}c?1CCcG<zO0XD~T(&3e1-b`jM"
    "Aoi+WCEY+dhr&fXm}!>sQ@0#S{A%L=)Bj)FmoT}FWM}>rguD?g)sjU3#3^|uqIGnS*1AGc+q-r-M4VN$SY(+XB~{P#f8XzWFB3?R"
    "tdhLr^)aI&!OTSF%lE!_7eN|_Y}P#oDFfoQb#W|uq?&>C#U9AH5*jPHNDg$zqQgNM1);<+;l439CyyF-d29kUl%W1H2XGA_J$&g1"
    "e0nmIRKt6D<O6QfIkv|KUS}7kNKS)>8sLW%R3Km;!aQL$`4~K!^hS9nr6sY3;~7`Q<+NHg#g^s58i>15bO39i`H<8(z(5M9SF@H}"
    "N>107Ow7o^;;EQXWB2Qpt?;nAs-?$1N~Ajbcs?68Dbn_^h)0H_V1`vg5fK&*^Ns_?;HT7Z=P{eMvuYw(%p9sA^tM>)@+Cg|c%GmQ"
    "I~%~zrfs{%Aw$4`tjL*lRYQ*eTHrpljJ1fuwr0R^3=JazT#8Eeyr>JQZ5{Y5`w<0qPBqF_i@`bTk^yLJWq?~8v|Mr2R(=ExvShRv"
    ">pfOM)YR;k#o{`1T(g8ZdB?l=9|x_US@9_Xh6cDz>k`5s4l=;HsBY*gPXOF9x?S?PVC5#rHM|)cl2<us!q1NxsHuppk^Y18ZD4h6"
    "E{Bt|&SC~W2LzDQ&4*pfV^D|>aXx1WBYa;1qOwy*1hD~Kr2r~9ns5lb1e!F3qWXf|%y4yi2V0jjdZ;OUc2@&wvL7&XSr)czsSJ`z"
    "Y2OS|Rw4!9%;*MeDq2U1_`f(i4s_ofH4cdx*Uj*p1d_D|7-Jv$x}tJZM={Hs1keoFeTXhEut})V0XPhF_?nRS|78(_T+W!?k+3aA"
    "o3P(Gz-K-8LqB6kTgZgF0{>{|&}RYW=fK-_3rz^Og~gPb`zNPLxSg_SM%}dIPUehHz=_5cu6@mjM;fdf%6zsFhjLVcEF@LdZ&K#M"
    "v0OSUy+Ku}p>E$l@in+yv)y9S0eK(pJLG-M?x+nwBg15=5BoqkP|dI%dBz+-XkJY6XT)1B3-qG~(70ep=I^awceQa)*EnRBp$)9V"
    "PcWG>&EIFYhML~sfR#^uEGQ`n_6mr$D1%mmHL}WYLK<lQi*p~nI!jX%Uob%=rLvf?*(h}8nvk|;5foqxyd=H4z~n%Ez|Ih>6)r|N"
    "zkm8ZHtg;Nlt9PKaxTMwnhX^?NQEYn*7g8{3@HH<C;+7crmlran$&Tgvx^J!jqhJTx7#+wwOf8b+KsX4B{nvdves28?FQ*UuAwJ@"
    "uvzUFoV%{TpSb}wOEp9ICU;LJa;_P~Dl}v#qa9E%Axj2(fzA_ytrY-|E!{L}RkSs@ei?A{Q!I&f?4fhTj3!HItB~f6cg)M1bmD4j"
    "VHF$WUTiP-Bcv2V^@k{gZaI%jh$X2s>DO$jO%=MX)1by$m;_hNYrg_^ZUHok!Y5zO;{Wn`tO)zOTsxWoGpktuH_X^ydftNW=y}Nj"
    "dI&xtbfD|!H13oc;9|@`^*M;YV5itJ`Y*3yx81KRX=5;EeayN6fdynIDQ%Zo3E2#ds$}8emfb-ZPYkUwfhG<F?DO#wvOT85EB)R="
    "n)Uv=--4Ev6~1n^pP?>)Zq|+oAf-XSt#Xzh_R~32!Wr2chhWMO>HvBSfvK<%#_U7Ss7t@i*-<RXlIVvPF}U=O@t=eqNoGe2RfS11"
    "4AoAdRpN^Px4&V(R#vbpnc<X&0mNV{P19394S#5U*Qt24f+C18<{UaT>+fNo0dk>$_<k5L^*d<UAKqssZ^U-4Q0UX5#wNuKG!4@G"
    "Zpmi2nA^?Qf%!7!9n@7ZVhM=7tg@K)$$8M0ka<ihVR}mfnNR;_0ilHJOBI8i1f%BO84cKW=PRI$fOS=K0*%^_{gS@TjCnHi0QzrD"
    "Bb5&U3ziF*l}k&gjAa4vevrWT&Ue7;*c?6zaz<@aY4DjuT^9{Y$*^)v!~*Ex@+lM7{U&JqP`rv^Uc?Q!Yjy8jV`Zgg7+hLMG{Ay&"
    "Gyq2pRFeoSE@ly`tSkYfvl<Epix0A4eE_u+5`WGEyzl<(SF7&<my89o!K#4e8{j~u=jDFO$|Ma-!{^WdL%+d-f+}EO7yAxC1)N9F"
    "FQJ*=b8!ZK@m)DuF@S;fwi1BIihUF2JhvFvCnyqV*(qISwUoHYOUN5=6Koap_<?SsdnAkW_qZQJ0FTA&^FV<d7ZM4|l0HxoBbNTe"
    "PUBWX2MF0_jdgcgc7|!@3}m6v|2vag)Mgg3T6RuW32RG$Df(fJ+ZcrmEMsw^sw6YbSbaWVjt|QT)PBo)xe3Gf*zOFXr}@FDM}RS_"
    "=<-P=38rLe5T89F7*mF=g|-L*k(LbRCn!!5mM4p2dc#1AQCprMH)ESUNMf8b5tt=*nL6FF{2l|$p_b!vGOQLn3IHMtSmC~4Yzyuc"
    "Te>m*!_@0KoQKWBtVQe&TO95RyL~2*%h*Dnu3wfCg#0Z_b~xqRrr7X|CCPm%<iIpl7-4tWas3228>N3G{a~G5L|G1%Gpg7-ff1J3"
    "ye;#2)<Dh{Z9|U|{jBVAO(RfK2W<UEb0gg%vDRijIa762tXUuA`ioObt75(uP}MwwR?T`3C3Ao>)};jl2GGn|ekzs@L}1Gq^Osqm"
    "JZlKoP8gfaWNHc;O_i`0O~xkGEGSu%Hh||UoD3jt)#eqwd3o5(n}A}YWGn9wJ3yfC$6;~TRBf^98e?dj(z-EF3cz}jhIIrSk0Bu{"
    "d^QcJfN4txqtfv~Z4&R9fqp7>C2uSCLWOj#Pgv8<jN_(d5&fO4+Y>`zF&lu5DOf>*RiJVfmdzk9=2TK^x_T4VTPJ$~whT@fPR%4l"
    "iPM{XxpF)@tnsPwnjq_jHSp;Uj7mtw7<gSO^0LD+Bz76GrYapU0mNvWNY3)Ta~+w4b5%8<*+CD%C1dPD$~p{jQ?m*UU<mZX0D3~3"
    "K^+0_sKH_8taSxpk{?@4*0xGBGcKpyRdM4c`ov6eFQme+A46@1kc8I3>hVPqu!1f-Swpo*DI(|W{+j{#@Jsp?lDlTBm)+%l=@#gK"
    ">Hz*D#kkrz!;)!#gf0MWAR_{Zg1OJkx2Pba0@z5U$}#~RK*7Acb0){bQUrAv02=vOmNYR-sX>zqSy?b^^8k>RCE-9MIV;Fw&?;ep"
    "@Pu`QBEXp9t~r`-j(pFsG8WM%FAZC$e*y0k@QGgw18EaR$p=8oAv1qjtEOcgVuk=T*|BNHr1&2ZLK>DnNCEnA3=syJD<WFUFfh(5"
    "%K^D+HhoBm)u6Egn$_UOMc}jCZ<OCTk&?K{@*K$$QWKlW(O@hcp9(S2RqSOF`vLQc;|zNm`Slz+K#fQ1c@$Ob(#&d*$1`r$67s@4"
    "@}jGj%K>?gh1fi+ShWBe5KEWPi33gufeh3VM-*)gm0)MBrbruRe}*`>x(sS4V}KPWCf?B)>C#5b!iDT~Oe2Ob)y@GDa@=6-74SY("
    "&pZmjEXphik_gH-lXg=uWB{4GJZ4KK!}ur;w`5H}ZdnF8h6bBSv1v%Cs0HQ#+fO5ARQNTR5@^2#Hp$q7rlQZPE}Oe1I+a-3NK|1}"
    "u`?f3HN2D0+J&^11mJ#AkV#vmXr4pjhwKkCXQ(SHB>H}P=R2{b;<m4YzFfD`?{3iGf#~Q?EP|x*AqK%4fuLI^gn=zf)-$7Eu)k5="
    "_)u5o^O*9OmpjW&U;(;$PSj=ya5ve3tZ6GKVC*h32bg4|^N^v-c~ug_5oj`Y1Fr<p!{#11XI#zT*dEjOEdB0P00}aY4sfEyEe7O?"
    "=@EnK4ZXBTgP@K}wxq)$rg_YE!q|{HgF=CK1$sC}kt$OJ=7^7Ocu6U=7D2<ql`C_$K}zVtqJOmY*%>WMSsECkk;WO2V~kr@Mr^4L"
    "g}A(Lrei?G>_c2#kYZc;Y<1bP!!K@9!_)wVe-&W)n6hG$L>YuF6V7Pvom1nh@0;z2gE6~-X?rC^NJ4vQ!y3?G!p_)CdSJK?6A|!="
    "6(MsAbW$=i9lCAa`r%!Z9ZUoDf$iRK2ZDGWq_mrsWy8{ZfYm^|R3M>6mV`L$z)1PZc;Fa-8Dx4)CYp*k*km){y97+n&!DFSL}}0}"
    "Lh#5I;3Llx(0R!8!!(Q%-hBp|rO+^dbCP*<JpQ1$C^_6TxNqy~)@i}RS_3paF;BBDXmM)GxQ$ph5@@lVOR4pi!To-d7WnTRqLuBT"
    "bKJxGW;A%zX`jI0>!zjWA0j;iF0AV|WEUxBCeRcW`DG2oykrAyRymEJ&L(li{z)f*)G!q@e8#9PO)ADDmu#I2xYGEzNqGeh5ri45"
    "hk!7^IoJ|13;5;$8eky+C8;0zMP1%AnJsPQI5854i8KQkqXCP4$trErm`#AejT#?%eh$Ea8AE_Y=CCJ4SS2OEIGbMGGZ&*FTzyw+"
    "(MkF46zmBSGmY8e1&SW_Fku=ohHTjW5u8N&?}cryfshUK)a;(ATpQ6<(Oo&F;-d0d8v$x%3*ZR^Q-a<DTw_0nioz@j_U|r%h}aJ<"
    "iD@gw9iEpt3uE0gr*Osfxc70%5b&gc7%8%n0Ub0xR_sTT;eY%rW^)CC9H_g%U#vyQ2ujcm!)fyByVI%QVV<RP3sROfs>4b$${;0~"
    "77Ab-086pA4Bm=rY0EO00Qv01!EAzzwWQMK^eYZ6>W{8M0+nPALEYlafP*2_z$~GdC-kyFwP!B}@RlZK9Y8kWVgO@YWB=#u@7&xq"
    "pS)lcPs>|&RQP>bv87V0u>r*j&x{@Sbt9#Vne7y@EMEcIiX$IN6d)fYdX$!|v>3GhJPOkYkS~qWh7}pvz&-q-RREBQN#Xvb#DttB"
    "#5<QmS_YI!*zf`Jux5fOqi>id!g}s()Wzz_(3F91qAbaRdzVt|cUKH7mqJF)I-J1WhIw5zb9W*33KqM;6n>IsESnV9Nr?Ls=h%fD"
    "z|@D5#_V}4L&Vqp$HDe$%k{~5ivsEcxC2usARy=-Zy}e!Zqq1Zre?wd`UON-FlVSeWExe?0K6C^k=5Us7h8|{R?|(jll;WPrpS<t"
    "ENhvva~lh5msOAv7vPr1A<MugY$Za+7nhQ;g>_Rgva1HcWO?(W)8Fj7Q?pliC*Ugvo#hxeW=b@jj#va62SD{;cRc6?{3A#paB7zM"
    "uc+1+`Tf*4qBaLG2()!EQ47(KQP<5_)~u;mm4R?8Or%qm#J1pc@`iQXxCltWV%~&FSb;?q-&qCAA8q%QWJ)b}rlaGDy=YkO3^xku"
    "9%EYo;u|6d#><4P+>p#!bB~Z+$^wBlSa=HJxB+(nX8Z9~Y&NT=IMpFLVsnV3QE{B)QBXnO3TY2Wz=nf)3e_TsedsB8`6g&;Y#fti"
    "S#%f*Qu@P7Sb`;9Lccg(0$?HU7Tb)c`8)%xVvSdtR4Fx~Z$@nV!7THFo`ZSNux7N+UdT+)3x0SBV%|Qn1uTmj2du-Nv6C!&$kMP|"
    "S0&&cgH73c!}sS6JFZuhfq9a%AP9G@^?!JNc9uAv9?CW(dXu&}<hp>ymYAhv<&LB&q?dEX)?7iGFl!!6sDa!nX`5j$wI81T22?1X"
    "gu4ln_l#=@+2aTpwFOQr+a$~~7EUkQu#nE<ZJM&VRt$6+RdglB00+3d#SgD#zpJKFf#7%zV8eVj@O&Woc~UWXk2zv#2Eofxq-7fC"
    "Mbt8jg6Y)MY}r(bx@W2FwtjRCZFcuokS`Vy3m7$3RzVgPaWW4Xs1II{(qovF5g;VEBIt%y>EbBJ^E9X#%bUdaE<<{@Kst;?)Pa*D"
    "!YvGww(-d=OST*WgGkbtwG*HY)9M4=v1W@$CbBSLqkvA60-8aNgvk%B;FNr-@WOdQ;gDm%d5}jSG%%s03Q8aYK!F;BkQFt{-xdsb"
    "O5*}-F)X2GYX6bDCtgZj(BkC8prE47+a?MV7W}Dm<{R*(Sg5c9z=hOcm^h#y^!{>QR~hS_Hwha>*7^P9*9WYfn3%SwByR{ZxZf>%"
    "oP<#L!wk}>j3VYz)G^B&r)-N2t(;vdfOW%$@p|`*gP~UV9U>869h?oI9T=~oAZYnNAvU5cDriPf9p*I5(=Jez3>;!=Iw%0T62SKT"
    "0vT{{L}kYy3>40Mp@J2G*kOa|qit9*6EcEM%i2}}HXvl1Id=48vMCrv#KxG=;P01076*Q34UD}hnud{81<SJ45p&;h(Ckf-0Gxml"
    "(>atws_i9v)G#Kg%<8fLqz<Bc*I*)7U1!iuBgF4AXQHJ+Cb7CP>%=zz>Q#YN1yxNS5RL$x5n5Q3LyZiiPEZ1kq-M;q57G=7DHncc"
    "J*LLT9rrKDQwHldejc(SP{5wpepR;xCSjfR5RfS)tu)|33?qQV3cwihw1P%cXZKFNUsKDYvIqVSd3;mUqa1FWZ^GH)TH=Vq7Mdie"
    "jg_?{Cdp-hjP)E}gBbEWV0&fiFwHzKleyov-<jORB_2ybz(MePAB>Fka^rbU6%c3(ql5N%5rM>kNqiq9N=ixC6)j1isX#FZerQ@3"
    "9v*UAR^0@Xt7&h6{+Y2GF)I>9EXDviGiM@N=tscgz^lNlkPA&wuo_xSned$jxOB&EJ|_>JWgBvKlZ4V8k|{I{|0ux?qa+U5-GkPw"
    "Ik>FPM#z{OH&^n%*{3-!es~RsaG347fGYrf%P1(p_t_7g0a00;vD5)uK!VDkELN-n8G}L?>kXX1>XXf}%yoSEzYmwZi1L8utA<(~"
    "BQXMIUot3;<+Xq<VzT#`rn)3&Fs#pX*Nl~W*h}VkmaoU9aKW{+5S+Zgf_*;%jn-@_8Bnu?<gD>dVFFB(CsiB+<wFY&8I2zS*p|gH"
    "GsCul3*6yK3p1$54Ow<j5tx)($UpK~nQZQZU=vU(JKz?y1A?K?*=36Ly;3l>?9^=5TV1Sfe|OSg*t?araw=v7urMpblVavcL04f("
    "qnr_(8CWC~yE&uDd}$B`rX2!P7WYk69~xs4;EuQ|OXfWWj4UW?+DU5ay^s<yAR*v53#nHCg*hF)U`in!%rR8P=AOy6(1^Ch_Vyt2"
    "qF_o0U=wg$=0gV58Obih!Qd9AMHSDZxtNBkcFryZ+{}yyf~fMN6SuFQ&~2N+KDRM6$&|J8=g>OncS*6KWtl+BEXZzZ8VPa#aTj71"
    "tjCpO+fwH0-80LPaWI15oW~V3{iH7E5^q?8g+hTW;~EQR9s0tj3S1J`ut-o<Bo$k>M@bU-cTcr#TBl6_1U1VGgscz8cG6%RI5lce"
    "4J%vGk`@CULe0<Vr4Cum7gN)-l2!FRvuK5|Ve6PWmPc&<RkF!_$_S^BxtKY`bkhVu4WJIOm^A?F^Cn?lL<H!>u!H%Dz}bGLQ7Iet"
    "QGlE&pmstA_-rbcR7|!7i=)M&45GTI{b&x{T|q}8a|Sdhq9|vv<mm2cwAw|tZ`<WiQ=?%b_MH6>Qu=)we=b!^ioC9Zj2*_Jgk@Q!"
    "uu(!o89vVGnWl-LEsi0!TY_SEDP~I2R9Ykuk}1pU0V>e8nFGjy!GeiEwz63~g)f6oVx~p_0W-fPxMLPKxu|6UV<4xt0n?13H8GvP"
    "#_@ohlXmX2Y6CkIv)Pwarho!dfleX@8wTmg7s;lp4GlSxS#rJXu8UoD<&;iJDXnV8D*HJTq+(i}D{%1&*Rq&1(v1inOb84#C251F"
    "K#yh@@;bh6MmoxlXDnNSL}oMjbPmKp)37NJq-0B%G8=I;AOe5RdJXYBW1)j!9<ga5<X3ygjNkJd1OED$ll3`#c5h%+R=jwXH!Qjg"
    "B*0qIfX8|2N8n;5wiW~eZ9b<j=tR6cL@(sNNfULA!z>Y<;o{^BYQgma$jKsM_)_Z+tfGO8XBZvm4~Q?OzZ}o{;O@X^M-zSBZrr+S"
    "Q>VHu)4mzMz?WldCtRHtng;8vRZM-Zp=&oRxl~GzSjhRf1@D9m&6rx(OUXNu{98tlmmynWM1+O~fJ+d?Yyp?i>CbjpxYAKZOM+iQ"
    "f5&m<c&o5rzv!MV+3fb&i}n8cm*qEcG*+ES)n|Gi3sNVHybPKc`bd#ehBRfvk^w;!0i*%av|zJ2`(zhbO^rhes7W;6nT6FJB&Rl~"
    "%ezRkti_3@tf-KOIW*x6GMukefz{{Y=FeE?xK0xsWnNI|hG}&)%h7w_=H}G$*pes7TeeGO8JM<8*bcshwncj>a7&dlUYt3702b_0"
    "6sAEiWbK}q!Mp==_JcME@MGGnGU&O$D%cB_2=v2>k~j6iZNW5B5G}5#4-GG4VHI%n;An=|5?^%mChWf&28@BJ+j&#bepfLnDuB8G"
    "Ehf(x`P0NuJj!|5R22(Tvl@EM+FnVSeRm%7K2d_}-v)r+CAa|1(lwnJ(9PP+Cpe~$k$vSD$pRh@3BtgP9I9=>0uM*?{4*^BMB@Fc"
    "uwE&%aI+=~S$HXkL9$>rQ39gI*g5D5dlt70bSpE~$ehPv8%J0HEAHMk#b!Ia279?NnF><@YXh+66{|VTp^djK4Za~w_3R~Bhgr(d"
    "cmS3l2d=1tpeUlFIZRktxBe{N4Hf~2*!&Sdw*~A5!PfNi;6&I@l^IPn(0mXwNEYZ0oGr-xIex>7bvSxAb9MOho3s=GnnFYapo2&G"
    "?Dozm9iIphSCKU&ao!p3B?H=6g(ID_Q3!NqcKFJMD28DYja{f$D@l@)BBYF$j6$Z{0c14bB_K1V=|-&80C7+=A~j)AjWDaAv`{(r"
    "@nLg3I>X}4;H>eNmNmphRAX^0kpQ)q-J);-iWr;6e)oXWKxZX&trG88MJ(1HLl^ds2OmN|&)3aP|KeK&c?8u7^a<w909wd*$YShP"
    "#=19HI=CYne$h8gDu(bNok{?F=x29LG@b-X6b=;P7a}PXfyF%Eq~t4N|8qZO^(&yV7W)O>$d*BE)K-{u?%=aw5@WfsN0ESWwly@h"
    "iW$Aw5ua5<BCscX92ZSU{Vk0nCj3Azk6AT_L41W^jS~lLh}8_wngmp@=V>|57{`|5hS3kp+6C<V7R0!4wDiV72=0abf>6RMGl$O4"
    "kB9GdHJtz~Ed=V9wAO^7qCSUUzk0kGP*afyxbL_rS;c;#DS>-DXD#8NNXz&HDOovgCP<ho2-OEFVVorp2S6%p#T|$9JPiOJ*y)%t"
    "@_-5~TUhvM4V(}9YMBMg%k1>0H<BU5ZAs@zTd;9JT!z$oLS~=h64xoqI^t4Q)G8Q6#sZyy_GOSUp9MPagFiSZLruB|kN^5$b#qXd"
    "<{!LQ@1}m>HQ%5@?<8T^Yqw4Fd*eNPcU5$a_p`_Fiboggi}lB=248M|Z`R(zsaE`TSvL#s)v_YWSYLY3CcU8=ubE)G`8x5cRk6pA"
    "!Fe#bSaVsOcXoF1;J2>n@GI}_hnLghMt)jPJZ%hfbGvHVowt(FoAZkYXJ;PQv2FfyzuY#o>Um|+ExU^~tpGfaqp|F-y@#(~ew=te"
    "10P*A)9~D%cuzk(_cmLPgMBGh80-<3f3a@9RjYlCp?-b$YW6e!!)x&vt5j^(c&hWd{g&35nj3QM{qu)&tZK=Rm%GNpKZ=X>*_i=i"
    "eDAJPQx7+o8??FMKZ}*8rKA||@x_QBe98JoPC;m_=gX4eI~Z!ShVoqP&d#_)JH9GW>sAKdT@^e0N23G$)OqC9TW*#e3H!dm16zEw"
    "YFLM7;`OmX+_{H5t@)z~Hw8~(-^^#xBk#ItbaZF$&o9>eHujp1j-_RHg&&Y$bS>|61C%zJ7vH4D2UdEq#unXdZuS!N_r%c1^}gGA"
    "%e7t54x^ZzyY&jM4^knqnsLsRC^!2Zz$dqz%WJ+ZyB!H}@eFVHzUiQuFR)u|=ZA4fcR;LN=i%>qS?&0)U9|zcAd&yWKX|_=jo)lQ"
    "H@BVwTTB0-oa!^yu)q&)_T9oxx?h743pemSynFt?FV_FIAQYY%(o<l(`1glbyWLIqcs9FS?ymObIVft@-PGUgbCT>K?vWWYPG&Sp"
    "<&ee|uwT=#8Y%-)s<vPcHOPya-Hz(0njKGuD@$r9un%A6=V5y8V-vKjxVQMxaTg$%4}bZ28pesYV0KNGvnCR2FEthGG$$#bPmn+y"
    "Kq7*Fv-fe}7Z8z<U<so(!-D<q7(lVW2EWAJN%FkEk}sckavv7U?rpdH+1%KLN0k%bfOv^HHrwS+>{Gmkyji^7+$vAgjk~MmjgXza"
    "7CqwtS?=~7j~L3o<el)IY(NF|vNI-VY?OCX;0jfsM?7fCfeD`(ljF^Dy(VwMWnDI3=}Em<FO*JZ<gHWv_cS>7@xOB9{pBZL^3K-9"
    "7Oe2h>u{Gg?TAg`Qg9kRy2Z2IhyzaWCe-GJH^VD^ZHmwR2eRG{3mS79-9%g&ENsblI6D&++miQx>}&CjbPh*R3dWH<Gh^dCmd&d6"
    "9%4!6f_2y$P(H{X^AxMi<)d@&oen8wkT&ayx4+RGxr?>=NRHY(@6ijPcfPoU$eHkq<`PGZosy5s#={}~$7Z?4>+_eq!MDQ;;;y}X"
    "-alIHx2!NA54ziW?)|*J#X_-nLK*#!CuFO*=U)M74`dHp!HA3}sqlK6%@V%)#KR4$iZw^;mMftQoZT916<-uRp?x`I{QU;WE(rgS"
    "!!bN%V#teQk>zlM&l<=oP|NKas{nz@Pp!`Fv6dDV`;C>_WSKUx>ZYIPVr@S&6N&&~iw5ttenCQ7uIUKFsd59&kK1Co!sDw=M-E+h"
    "CX~%%$R*C@5*+_xtq&Qg({A?bT16Zr4nVxO+R(#<)4{cEhyi$@H)7KvwSvZ^9;R^8iDz!o)DTN=|8c%jx5dpud4{2+;~!kC?Q4R{"
    "a1Qp~F2&;`f_HU0erv|8bx%Md<RjQ!tbOx&f8!BZtQ*L|uGrpkuM9u>9a{n7==LRq%??~d5CXR0TEqyikTN&9eUR9O_L<Q{pd{9I"
    "?=3~;&mW$>eCbJ@&IuTHIq{yom#1I-0@g$pD7E-7A(+A-{6M$>8}hR!-kYZ%-sv5=p2|lu@t8!{o9#6)#_zlni=W>-Uw9?h8!j6U"
    "XSck(+Ns<IynFi|o3150$W%H{+R{%9IN~(~nP3&*fby_sv)xGbawE;wg54+xA#Wzf>n|BWR?n19fxS+4wBRLJEiYv%3#gpt<!9LL"
    "1#q4B_C3McbbjtjK(I(={Fu#2y3L9(u)5kTxy8ceJjUcd@#Lr23;uQ?u%xiFOaTgR@UwMuDev_}aOHb!JFWy4#a%cXy|^h|Ml34K"
    "dNyLvvY=JB=?5e|5@rfkao5gSUgK{-RLabMIUL13R*xLk(1yE<=iVFq1-53XkYud$D#z1PJhgn>0KBXuPrBcCJzK<@KCm=(wPTzg"
    ")*#T;TRh)XQup9}(@q6uJ~qgYABfb^Q}Hyz_+scAqoixO?u0K>Z@k67y!`l=g<)`%Wr9|>jrbM$UbDsj#Gy%<F#gJTd3#W?cSVKS"
    "igWM16h|V=2B)SyrZe0eBi-CIKmc;h%$%MplphMYa8;h%kl{~R>7yr}T$c%1xbBIagE!wQN8~%uA)8&ps`SehKOe5OvWz}t1dDRE"
    "hNtS;d#tQ>x8LG7&c3({2E*G}$#_BGEl`NS=SFTv|C)++Hc%~a&8p%?QSEOZf0<@3%PDq5Uy+|D-nRH^z8BUhZ`OYSVL>g0OL+R?"
    "m$&a<;A@iV@>(?u=LLW}IA$2fo)l;hAaZsVBm@5e&8$GKD|{u>;M-7^g+C5xR7R6(9QeY>9Xw+SrSTOW^0(cR2f%wK2ShGdtf(2>"
    "del&d#XJJ7Kcm{$QL$S*%to_464vn$YaM;MppsEh72;g(S0oItZN4^JWwgUYLONbHErA|WE2ZUpnz~bMs%vh@^dOofL+fI#g2U2~"
    ";rl!doYRb=vX}O<ZQ`Ol`862U6@;_QLMEaE3k<Qsou?|l1#$2aTLRY_^%DvsY$zxUw|Ybwp3KA{%r6%MJ!!5PE|LH-7Eign(nl@*"
    "n8W1n=ztf@DI+PtlIWM6{&%Aq@{&e{1LB-H^w=)99r5I9wfPDfkyphm!vkHz_IMLL7ek~o`9t0Si`ep8@=%<I+-fe3R}lXx5^}^<"
    "d6~>6-Vn<g;;7Hg_zruyhjur?eW>*gZ;uya#x*Vg3p(kVWJlW-Eh^)`z5eN<rwVgGUIV>jJ2Bh@vw%I=uMXyr_n5h_V8?%=>N6Lw"
    "Pl2Uuy@Qt>hC5gSfVd&MR?YcFz^_(Bj(FFS_z^z?vJ~_=Rq%O&V4mm|=ye-wyP8__2oH24)(cLdmaM1uSxl_<u$7o7%M5@~));`}"
    "2(nWZi|}JPuxeShqCq)h!J566!~GV~hqDw6tE*T+7O%j3mTQh9kn!xym`glclL5=1zGZX`gJX;dW@LU-0}4)~1X5C61FZ6ek?=S<"
    ">dGU_iDzmR$#z(HDe4Wz1|qLThFNq{LYfb12Zf&XF}k{v+yaPDvRa}w!A}m(v+9Y?Gj)KpwFX>*74M9WBlfA8wjm-H!1;7H8?jV1"
    "st#H-XcU$ME1O{zN0u{VGm`Fc_?VD%J$iHO*w^B=qaaWz*cI1QRV;Fyx-bhE8f&hujDC7Bmr!4iULDlhjkdQp*-1!@N2N%Yvgic?"
    "haaDUJpl@+LM<s1!?HO_H|h6B0l{wBSX6|~6{IjwQBQKv7m3~lVd4m=wm@fV1*Y+1voI1Pq=_=&`{22O)Z?>pjd5c-mcI-Z#qJmz"
    "-<xJBM$2Nb8M>q_Ovn?>kGuKX`&StEdh?|*a?_GstEc~5ZZGDrc({{gY<G^~lDA@HcRD+zdf>uwX9&E_B@()K7@|n^+g=wteBI$K"
    "J8OJ=cVq}YK~@jH1ieMxSYzwnGzoHPlrt^Nq6Y<fF)^C6>fE%A^rq+wG2c_6Q(CknD3nbN7MnwMw2)gm{YT2rtthnCc)6_qypZX^"
    ">nKRX4qNRUW1qd1gDPs@aX3z~pNNKLhyjv8@0jF_L%Q2bX<6ddnw-wgp12pgzgOmFgB4k3g*P{Xo@)K*jVVN0EP1!EoWOnnLMen0"
    "iQO*NU%}~xI~pS~pe@#S?)|1}2rV->F6b<_Os|;LEj9MXL^X(ACAb&co}G$9CoJb?yCmp4J2P+=tFh)Zh@3(O@@UBBDMBSZGaSw_"
    "$4J00lp2Wco=jxP6J^@YaR_f9#S0TrIMbiBXKcZf9$NS29Oxys^uGKQBzJyJ!aHAhCj1&auP>YLiPEOZ0K1~}^Ba&$qf|FYCXh`r"
    "Ub#RIJzSL<v}G`inZ7CAPB$iHVcc4Pcgt^HcO_K^)I4SPUj(|v*r4?i`V^G`i_IL~I#gaZ$7n=!DThhZm!4m@uV^`H_bVE!dN+Wl"
    "|F$=HBz(l6YBJ~yg#BM1-oEMO_0zYn&7r;e1sv?F*sA1|NbP55QhdPs5*UlEkR;Ycbhrh-+t%#9$jd?OYBy6KQw#9Lx_>#_WDIn6"
    "GZhU?4onIg*!}iCH@DrysAXif8;FlA$U|xjIB>#mBHa&?X5$HUZ#&~8w5(1|hQ=1q8FsmrQbQBZ40^Gq6T-piq~?kD=9gzZ5qocb"
    "do{BX(|Hn$-mh;8a!D{bAid3{@_-j&n3Mfw<tv@pGSnxYNt)|={%um&cyx==>OT#uw}vO#Qj)=TTigoFFq<<Ed&sD{N1eH_+_f40"
    "V=f7_h9GE)z~!To!vn63iA9jM>Rf8bkxYi=ZZC?yo;`%1m~)KcM7+$yRPE8DCq@mEmRJNoIMgR^@R(HkH}4l2@o(PyUfM|JL_vM#"
    "Z+Kujoy!07*+qw&dR=@nTxx-zz0{5K7Qv#ICHk!TKR@YB?>@PH&`(wb-*SkjdKlhfx7{}jK~}>4_uT&{maWdDXp{p=br!i|p9~P9"
    "6f~do$Hp1n^du*Y(w^6t>>$y%d$|C{b2~_DJG=p~W@Kw`?6c9$l8kJ|qC`BKzrdL=A6KKaX?dOoxl@9Q8QFZ=gAy^vn}G+A@oB$Z"
    "ac~9EpVawx=hzM!B!uETU|cJ2;Qo<6<y}gm=~V+JDx+GLqMch{JNK0n+dmyju$#;;TejxB>}Ir=v;(sjm%8rmWI!K>%eC)r#uf?W"
    "c<ZbN!Dwk785o3Fu(;`|rC=;WuQ&C#Pa;J=4LF30eb(OvM?#5de|YXm?|~Yk2&^u6cuo$=(V2Bp!%Dj`5q9eBR{kLzj_Av>UDE%V"
    "x`)p0Lt4X>uDO{?H%(XKEPD@?dwZ?U4|9zScHwCcqRvij==V<k$GfWh&0LXwyB!{HwPkmdfsq4aFRzWJJ3u`3qT<tK?}ph~KBD-x"
    "r?ejN-g%?I^=?M~O4*FjO%l3rMwGwr8c)c=YW=5&yjZJBest_0RblGDX*^VAkQB$X77lV8ym(<wm~6v)ICdv_#_9BkHxJAb4~SFH"
    "Dn@3d8020A|47);?g~Hee|ica_QMUph(ERaGyHg9AZ9Bd3=hIQ>`($19$6)2EE=rQTyH8SxK|?3a0}(8_wNi*KMPlfvlnYct}T`g"
    "MU%Y%F<u|q^tz432Aw|DnOlf;igT+Kf$xMikSV#gdO8ya`TFyRk7HB#W6J#fmdYvC!-`nD#yTM62XCIwtjU^w3jk^|32fgIB(mNx"
    "V5x3+nU`yF1aZzx9Q$|U3?`3Hyc_Km0pQAABHivgvIL$0of<P!4R&zVbdc>FqqF8PU60zsaM5q+XrLm!arqs{+Oo&0A!!#ajg2(a"
    "S}UrGO)FMN5}kGKac%hT1;8iG;besT*xaBe_?dxQGqY>75cKR=Oi;ahMd%V5%zoGVw9Uqflani{H;s7NRH*d+6v6F4SDRIB9Or}E"
    "#a^MoBdiB*4b45;H^xuvYw6kAKo@ceB;aFT;ZX*O^<c|rWYu=lb*kT(OVzpTT?M9<I=#|%AUR(?moPk6>Q4@&x?_qP!a9cN0_8a7"
    "i%yNp{c_aO3?QX9iX2I*u+8*|bMF^y;Fmy5=^zii?Pq6V^R}R>Gs;oV?I%Vk=#oH`KXry9sXFXPU0x2pixWsU>)*jx8jZ1Xxw5cL"
    "?Xr?2R4rLB%X`>wE8h=K)wOUzVs}*<A6b;ryR!|;qDKR(?9I(4W=51mwKR^ms8?Y>x`OZQ%#x#5ZEtUO8$5h-rI(u)4HI~GVyB8r"
    "jnz>Y>YTJmeWhl^wJ1>9ZA{a5Q1y1H-D4!yrJr6lM*=5sb#Y2Nvu^f07qbIyOGzv3XHv_$rmL|>z3MZPENmKI2BYHFX0@8Cv(r6T"
    "u^iIcqLzljf(a)W!fY$ug;*Y)gTnqQHN)9x5UV;f%u7u^z04L1wIO-kb^DDu5b<nUeAla_7i(3_9i3c`(rOI!Ue2?q_nC=HQv{9u"
    "#=Zo}-FP(ddF)x!1>S`kn*(Rf!lt^gA&Tc$`Fmt>rAa`{*9HIzN*N=C1uyQ@c;}}tdk*(_0rt54Ogh>rrGmV+BC!jP;~K}Aus<^S"
    "l|)lsx-l#>31K<-K-s+-DXPtihsO8rT|@_uo5+|~zc3c&)i3hwv-kKO7gg5LDYcpQbe>jSB#rTAU9O2#o|q-uxCRk11Km-=Qusnz"
    ")M8AME&5Vym)uaZ3vLjU804<Y<>h{}$Ht$X378}LcHjgj6w0-PR9sRA---5Z?)PJHhO04`c01lk0CsmSMk!oxz9`cHRv+H#Xg0N_"
    "46#5;t~i%31H~#iWA|}U$>M3qAL5PlpAy!1V`51pN}-m^N;cAsJyGJ4#lmRWmyst2wk2zq5>w^c#utzS@F$L7>#A+jtS1*T?9FzA"
    "-{Su)(vv7%G4AsdoJ^-o-im)CN@;P$A}@K4r^2cE*6Ki!tV{`|*)rV8lhantj92sibC2J&w@(<ot@li0eQ<&B&4}k4I#OL#MUwH0"
    "sLe&a)LhF?oh#AQ(nUvBw^XsCd`Dw47w4CBIGDIpC<Ydtb@l`;dQi?}8PKn|6{9`h9x8m#-cJq4t>s1y5pqHgs#6))r49IX{YIFw"
    "Q?_bd@B$D7)u=6nYWx+DQRhS}x|U4_TPbRu;fGV27MSF)P(Wk9D!bbKYTKwjB+(jrB-VLs<5i8Iu}%_WOUolOxtLnbMl@a!sRO%E"
    "f1CrAdv8NGlK2uc(PO(oWuCa&zM~yEKocC!8u~8QwC%ZOy@^KOkTr`$(C;ka+gs%jtvUamVjl_JEa^;FEz-ds7x<(TMxx%VQ<q}U"
    "pT8E4q20K{6<Nya3x?bZixK7YBn&b69<=lJQKcY7ZtrBw=<LOEf|NAX!`V*gMH0+4EXuBR=5hvb4cvMm>zNzMY1<39GJG-wRFR?d"
    "omvOfZ84ePXf^n&so(f%BxG0JK;pfz#@RkF>#4yhYwACT7X6Ks{MeGoI_@hQXlQ~C4jkBf%A69T*~jDp+iMHCqbid3uP@(WkvJBG"
    "_Y?1bzkW4){_#2X)wX}v@Sonrt5QrbVhwH9u^Z6}Zb9;FU_=vFlf$-NUo%RM_qNy9G$3P)gzXCsI<e~lhm04mn^2h(v0F)u$e^;?"
    "-@5NGp|UcQP-J)MqzR{-sdws4uro8Y(@qEg8eXnpSX;)y<Bmcs$(D8pL_ECLtC!DSy!r5g+{z)b*-%H@**LvLzrK5AZ!XEccX(T+"
    "OkJHca}}RQaZR!-5+^0pX^G78y~iBcyA?bBaSUr8Jvzjm8W+5|kkjD>dB)6_*w`Rt)$+wtY0|&kbTPZ&0fmDZ)O#IA!t9993Oj5e"
    "DH-w^(V&ekvr!Go%^eHv_$@`={H*qAB9c)Et<A0J(_q&7%Vu}J*<Q|QJDAweS+h3;%1S!@=$;M@9fscd!i8PV1u(;mOjx|7TMH7$"
    "@hm2~ZP^M2RF{u;rMmn$yrR!?!z(UG&wnC?AKR-a@>O;Wq`m|#Su3-7osqlyE%@;unC0eF#a5Cn&LndNGWaf~Kuj->O|TS{O7+lp"
    "hYU+S?rs{37+EMAmNZR~J{%L9YK;Ov7E;IAR)b$y6g9j6m~o@V=VB0&M`1*FhY!g$IQM=Le}-ikgoV8-YYlYR?A5Ytj1O4lUBAmz"
    "*UDQ>dr|uhm5ja!wG1g-iJVvI<N#%~5SMg<%NY+Re{eF6DZy-tWFlH+f|{(c<#0P)6Mtt+AVyTVc1*i26=q+G%e`|2a7f*dGk{B4"
    "w9Y81Rd2Rp4}-K4X=!e(rU{By#fGF~u<MNyB_k9xp~w^6!6d?b5C^>FuT}tZQe%f1MAvq|x{DhU`GB<cT#tPb2KjW49dX}FL&NMH"
    "-@U{3`&<|+9iiiSj#RZdJM0@yiR%b{H*i`dGNy#|7X0|)8&JegjApMywi*wid!s8u5?vqS!Pq@zn;)SbiE5(3&J-b@6<$s(iX^L8"
    "uMqxJZCW5@2VkYVO>Gu@kEd^6PesA4)shh;-m4e0r!Txp?CD16nOite{}ZDo2r$t|GWjQV*E4!^rwJ<yQ!{IbKN{GyBp-<D$FM6p"
    "J?Jmz+kB;;+s2cPan!kNyArUq$n4ikydBUh&7r*^p3Shy*EC${x3!cj0DGe<K-=xZM+;Y>EPLRF9h1^85(R2B))6}p6`cuaVh@nu"
    "K4HTHNy+*qqIGyCFTs1baA3k>W?eY)*CS&zwF8LyJVfZ(SLyb2NO#`CByaPl;;++?U1|R<t_97!s>EJ4f-Gbo_Kt`t3Y<e}cUb%o"
    "4h~IF2Q>jCqKJsf3HB%CFJD@Zw`yYeYPdU=+o&4`VEzmCu5h9RFHG2;@!OwDK~o@sNf#y%WihtcV(i~EYFK{06)4+luS2+woSRi#"
    "HTGwmq4q=!Q$w8I*ppkB{1!P>>!GyNOZ7mtU^l?W1{<B71$m}AC<yam;79!rxusT1ePq)b@{}S5Ym+zUC79S3ni}og$pzHj&IH}S"
    "LYIPBB)X}OVd?=JIOo*HYI#n$({g=BxD*{P%xL}OK)vq#=5}Fu++bQ{_{>Cz!l+vEO1(ZMujYhRov^Sv?153zTQxK&iCG@~#9K_K"
    "U!erD>4RDT7HWdrHkZ%`x0<f0DX^NKtEjC9s?6{e=^#>!DZ@9a$*G-PY*@?*zSWuO8`-bPe|iurK$_VIgvZ+@{!^0Qr&Ih_;LqN@"
    "WEQ)%(5P?8MEKnpBdQ<=C606NUr0*wiDGDo2^|6&$VAm3p)d=E&d$=&T4r86_dY&-u89PVi@SU0ff@saN$`H{8OiKMCLHd+wE;Ok"
    "9^=zi)lP8vt&JtR5H{b3Gm!>*uaMy3t){iSy9GvDTPbN__^@25Cu0I&-yZ}xyJo0|Y9`y<>_DuKG&1R*)&BFh{^I}5d!r(I_~6|*"
    "QoIkSeQ2s*Sd{r_6wBnsG<~>TSFJ?qdW+%T=TBF~?|?-gH=EUGhSr4V{&|227g<`hNt(ylo;dK6Dz6hZ{)?Mr-lQ!nr&MVa6j|(t"
    "5xYs2^Rg_;Ad90aVFe||7c82*h~uWM+iE_~;wq@yC=dN4o99WExAWEyD!*)F_A*U^xz9Gai610$*5xg#GUXryh}iH^Jq#&8u{Jix"
    "QR-!%ET9n(FTp>GOF^z+!Y`o;?V8_S+P8j%zZRZ<K0o($wQ&+xX_fl<ylv;~<DIb8PZc&v+BSJvMQp^AHl-8?%S+Z*#p2t%#)c$w"
    "d1bs?p2vAJ$3KF$zy`6)9xL)ktmwqPk73l#n>@{mmbI7Iek4kYv`8Zsru{o#`C|Q)LH5enEDkad+*|ykYisz^#REsTfAD9_`j1xi"
    "{If<)L%F8Q3>3#D*&jp0)cb1rw{=jM2n4OmTOS!uX#8DiMEUq&%s84{N;D-YN>lQjTU*6rqNePN_0S4v;4lmir3DePPU?S14DE4U"
    "w*{F)r#jvsdmMahRDlsTSjyZ+Y3%?-gvm%$Go~PFQCvYVVB?3`t+_K?TLm~a=T{rFXbet9gI0-cl}=7)9C@}@3(LbaVi`A4{)YWv"
    "v-S2nfn)?rlzb+bpRie992?CvrCzG<zHZ!17sEg(BO&GmA~@E8i#3n`I6Y-y`OqgD*l);Y?VV1UvBuM54c8mz$7o#ty;(MjJ00Jz"
    ";~rMGXwM~Ok69(8&!{x6S4~|3T~e(UBe<Bd*n!#m*=zSA2My1)Ia4Z;R6u*`+PYTf+{L=jRu&s#pMXmhy)b~q(TorDpRUnC+{`h2"
    "Rj>LGeG|YUg692x?fP!|SEtG+A+L+Y;)Zcc-Bq(<?v_fh1~Xig!v3a%^;Tu=#RW6hx{HfbxTzmu`u6V`<bO2lFOOfn!&e{v&zonz"
    "{PyAH+c%%y{Pymje)az3{q*ed#RcyR2H9L(bc2}E$<B8wrp`r5X(`B`+%aFi`Q`o3zrOtN@#V7*ca6FfA+TTCF@eLIbCCi4fPe2^"
    "dDE$hvzl5q^xv|5_l^7a3@TV^YAvf%8`k&VwdOmA2Z@qWpEqr>U+th{2@dnFH%z433VU31p8<2FpbnK)hMK5_^~sPoB+nbo*4}R`"
    "Q6zl<Ba35K^3Uw_!WC?nGVkNYDpbSHs^<+#xdeKd984PgD0;mk9y@WfCv8!kg$h06SFi=wtk2J;z^R?7cdM{M+lCdUjdw%bPFNcx"
    "5TL)9y=6~bF*FEcGuE<m*uq#QFi)si-t5k8DL5k}J~z!xr&bqTsbTefbS@bVxux<&7p-&a9t)~A+o%Eg)&#@8HIx{pBpa6VV8UW<"
    ";fZ2yp+{rm_5PX>u0uYoCYSBEHyh(hfq=bi92cJ|eBsnKK-AbNsbsVmmG>%ers^r@QH&m+8ZBS6bFyNS0_nt|j3c6{x=5tQVm!{K"
    ")EW&737H&R5tRSN;i-Ov&NU_V7G$^LnVnet)hhL>;zo{u^{tic=mosJ7Mou~iwhKflX9t=&1zXn$#NrYuM5!~Z94TJlRBo08LtM7"
    "M;l}Irdwo))au<H^3v?ZfSb1jrlO7mnS*25FIPJ&pbC|jCK>W#4J7oJeJM&4%@<-Hl<nePlT+*nplk@=rlfk$Rc-t9db>}D;eY4e"
    "haqEW*oh$uYxF__t^1du2Tvw+(4<+ro#Ll%aBq<+ic165dM}tcTM0YT!^JKdVyjF<ni6>*ly=i>Y3T)7+81|ff(g0Fraj*nr%fvs"
    "#r~}|cHv4jZsS<s?$;8D11gcQnBE+NgW{K9NOEAer}5XM$67MxQVJm&zjLu#Y4JlTLMMq)*e=n}-63X93B@r!S4%?>Xatmvn8Ri="
    "n3r*T&9q;XO)s68ce1adVRPK4x*j4WT?}|#te33>Yi~{bfH!bJn;AtcZA}|;EGGH_9A3ix_vLn3&7?k~Wo6PEP`UgQJzi5mZ(u2X"
    "JTdM1qf}~nUO*k~HR`F@HewZ0>k65h4PrEzQkrM?a|LNfA|nD-F-79GPd_o&!gba3HWaBSv1wZ>5fbM3(xeI-iweZ-Gi7TpsVpsQ"
    "K@?L^#M<wM*o*RZNSu_>dSc!-c=@$W;9g2iOAYUl3o#MPv{!8#(RPZJc;=gGFUH&26rN%D<>K;6%4!s=JuSPhKRlK5-)yZ+mn>Yp"
    "FxK+&p?4;_HcGRdpc_hJK05W@LQ^93PkILVX8&s=j*;$h9|oC3-s|O4xdK#^jTUY`-EDR}UXMk3`UfUjLB?3UCtjul@Ncl8UYZ+I"
    "6irX+>99Eo98a}RRU4hGyKxp5<Lk&4vGcnb{(o9a!n;<&n{b#uQ&qr+o7s9`-k*5g?KMc_GtXizp)qo~{&jhiL=%0(!A&c54QJO4"
    "NL52k9ILnX<LPEAphZTWJbVAlX6*L^a6F67+HG+y;li}LQMI;5rtwG~fFaR|6A5YxWA;%=!&qNzacX<5)=<w#Qk90e+cTmMkT)FU"
    "NZe4HI0?@XfD(>`pvy5V{_UBD8h`r8@Qi;y|8}i4pj?@0-|d{F^}@+CA4Rp;gA7O$JU{zdj+0&&(fbbN1)ZpoDGQc~&6hq!=%~Wb"
    "JdNrz{;`LBW!9%}Uq9l@yWTR-bNyvc=+rkDSaAeBe;|U502J5BCt5Gifw$Q2+G)1nP#9bO3X+Ay1kxza%nzk6wh6NFx~toBdfB?!"
    "C?F44@@iQwb?3a%&H>Iq+gN{|*h)tx&c_t?scnpp_we-ncx1PZl??`es8f;F>ywtqPOVwk_=9*ny(AfeZ)DXH7Ng}-_UoSMb3h4s"
    "V4jspTQvEK_?M!F#S@A8F)%}YfTEHN?<*wa%x$>V;~_Z2DZKhuk^O(n{>u0I1M}FUmx6Q}(kEcVV?7;_3^qn{AwC39Ak?gOGlB4G"
    "$d+i7lT3Gy6g_b&;E<C{^un3;Hy(r)A7sUko@6A2sbyBAsXu6fq?{ZEd!0F$m2q^nk0Nb|v<zp~BUj9*-pw1vJa5<M-ZR}vLTtXG"
    "G2=+lZ{~V3$&<n>n79#+IJZ8b3#$_wjABd^Pu*GCY1Utsz&65D<>-f6e9C2d3ln30)na2}@%0$RC~AUD4KlNdg%<mQ_2C}VHb*tl"
    "aSYd5bV}$-4|w`lrJO&QZ%WSc@bH@H$AfG55zv_yK`|+La%))v!<6u6fbK?K-A2uenOPrL9GuBGt(ZdzD>In^rbeV;$9?gI-icw-"
    "YOo@e#}u`4^;qDNgXsz5;Bj)IgUX0go5*7ZwgK}GrSgLP^U;%mE;*L@*q++Jp?gn?Om85ad3xGP6;~6oY%Y$NSXqhM%AQ`(;Fz%V"
    "B?Jl&+xV|^FU=v2_%b=`z?)5_68%aTwQQopP`t%E9d04lZt<c1{HKctua^uJ*tEOzH!nV(<FktgrX&hajZg&ohna(xt*v4d!##&G"
    "2pk+Jb$9zKQ^sayS6<eOA=}aoad`P$cJ%~Te<sA%c$a$!Q`S~8K+Q1MA##!WfXv8|Gz#L>cm~!0kkTSb-ubcEUN$><OF^vm{p6O~"
    "(I=*=18e@f1pwqSG+IsDdC7xHM&4kr=JU9Tvn5S1yV-~5|1{Nq+I&L*Uz*IB$Dn4b{ujIES_e}bI7FqfY`w%cFHAx9(cHZGl9Va$"
    "%)k;k>gN_Gp37dIbLZ$R-X4Folg(iUZeP=wGi&K1l}eT>srL|M4KUQxMt<V}Msv|zm#SeyW}u(63d1mpyso*Pckm?<5-wljct)e`"
    "F}`X)$_KH`o|1-$borT7wH}9MItfl9MaMVK^3q~AyuxrP1dea^JK2c^1i@mqfNIRrLc@3lr5mNLad5e?LEraBg*`w_eG-K+wG8<q"
    "Rs`@xXNK)sK_cX1%@fc5!O)iBzO5S3j7IE9f4xou`G&Mx&k(E8{Y5i+t1mY-Si&aHIW;DT;lc6>dkGDT-hm$)YY^Qh)XmyvyLI#{"
    "soA9k`7N1YzrYKmvYN|`%<W$`nzJ{c2-WKi5onl0b5Q5l)jvSsUjnP}xk@o6sG54eZLD`h%&E5GWZ^tXb}z*t?r@)+iz116MF91#"
    "!a=EZ%bpqW#NR0&F1+rFCt%KfAevKN8E9?LVFBmY-gIhr@P1pn`mPNxdv88A;v9qMn{JyaZJ~WBc=2plv*DDg5#M?G?CtB<FF($@"
    "Z8dwP215JacEGzH`<G?S(B!J~E*?nwkIEXa=dnYAgfW5{3*-}T_$iaA>i;Mz4IP%R4{rAP#e?2WV4R}Y>h>#Y8wP3<ZC!aaRGQLU"
    "t-eUzTJo1AZt(r90aRN!c77+ip8dYOnOOj~P(v<mvBaHWw7-1(_|6)3tcd8Wh?ou1#Wj3XjCs@)_RTl3sE9*b0(Tl^PWq0;ez&1("
    "vU2oTo7-yQ%uUmZLf=k+y@!pE1{bb<hS<B@Zocw+W06ry3r#ej$s5UM`T5;TQ`J=rF3_LE3v3+5dP{95B_qhRPJs9E)d$b%3+p*q"
    "V|s31HkHZpG;vr4gEecBs^{Jd7j&zS$9UYoDf4hQQG=5l{_uolm-(WsTy5es!DrT;a7Cuxl^Urqqz4F#1YP|4;v-SLv8>5VHrQEI"
    "9qdcuPfY@@SbxO+zF`qEDAfP7d@9)_%#3SHYhrdu*xAYe#%`n?1vCR&o|Q^S>iOy|*5_Oj&Qr)Lgmke12*w&QePI<YmD`=Ik#i0*"
    "W$atzN8a?$ti%Xd%dw$*Mt(4h{JDJ2<Fn30`7X?7Q5?v3<!VD);Nr=}I{x-;W{hkz^Rn`Y6Arm};`P*OWq~%WXw;yzsU>IWVm%}+"
    "*;nt(VEysoVrhjDi5Jxxjb0xe$4tG_2rAH=@w(Z7MpLWIa=Do%Ym=$BQa`INqfYIS^<9mv7oZGh<Nyh=9~s-Hz^Zfa7lM*o0L*J~"
    "G)nDP%Bg3sUTR_5&ZK}k1=Gwrpz*vjNsvN~_HDQe;)NUGr`-m;@k#<Z4Iz`Mm>>vS>$K~J-0|~6)@VxQ8LOwFDWL$H8rNs0h&&r5"
    "$X{r&Sg94u%Tj8kf-ePKq$V+L=1OBTi^5HthAIP@&{wf<8#DCa1yjvfvmu-v6Ke0Tg=Xw7rQ~#9&tPXo|J#8OJT2EXDl9cPnNJao"
    "1pB)XQA0qli*Mq0)Z47JZ=@!2rc`#SvRv=y)EHDTE^cii!U>N9sqS?j+b^?g30h`3nNV-FSQ@A$#oaXNW~QZdC<N+0R77ae?za1?"
    "Q<DZbv<_kzv&twZJmuWL5^l`J`mY3_7Z1h-&@LW4_JWCiV`kd&vkP(IPJ7?uRHdi-TrVEjU-Wgt^fw<Q8TQ;DiKEAyIWHcZ9!V?o"
    "=o9}4wmQ`3xoW=sxqp0IM@%0-VMQC7RrS9#zE+(e^6#F&u<K8TrSKQBgZ%br&Ql;`m|OscA}uok2eE!+%<yTyt8~E750h!&Pv`!}"
    "Abjlm_`iR3e$&f4eOh_*R8}!%yOKeC&I0FW%5C*G*1J?Y-*bRZ%Gvo4q!PdR!)}>!yHAFxjdnsRs>-<5%dXtc8T@-k>P}^<!S(!|"
    "zxp>F=&u(KKI7)=I0jE+7NH&7U-ND!A+15Y`t<jf^T*`Gd}HYPy=i+G{DU)c!hbhAV04R5y>4M{mM9*5ZN`zSUzO7JfU5uKf%R`)"
    "b5MKNt-Cu4Xpo;fpPGYQ^mSo+GnsObzOzkW<3gmt+!IgoGiXhufcmLZ1A${MJh!!hRYYo^mvL2~m(Tk|U$rex##O$YmT^uopx*Eb"
    "{Qtz(;+J3wQ`<|YI%N{kBnxlA75b>j;jtzclXd-BzLOFmTJB9tFo<W>rj#5a653;S^p7$Ic5!f{9!n6-5Mar&7~(C}#pt`3Zeapr"
    "w04Y!<Y=wypB*S{L<gq=Avky2%)@l6X994|aMT<YxA>pw>(|q|{`i-_Jifku+;#uDun@%L-(459A2!ng=(x(aLq{fk)E0&rvOaB0"
    "&%~xLN*hesB@<OE6<Ob^M_c=F8EwK8_!uHPm}&^k>WZyHcAkb5*GmcY#U9YTFXjPDX)_DNq^Xo!;!S5)66m)PlndQf>~Y?2#+}#W"
    "tI=!QkN{ga*3>MMJOt_f_ryqPry*0}f<Fl=lNh5vNx8VmLA(Xanb@uXn}gEiHcrA@oQuRZx`IuVQ9xzNz4ievCdP{FUh)*4Y7OhZ"
    "d9MLuY#GH-+0?#!m*F0LiNW3-&(hYrasANgUV=$Pl^8M|W_>MEYns#OxRyrl!J%hOTBh8gG9|~rIyFmjMwZK^o&$BsI4(KY;b|7B"
    "QC+>HpANT{V?K9&U>7=s9hucl)Iw*OiMi{}^*1G69q8sP`~6{gbmuwgg)`u1GxSeRM7_J=r?4R=_-(-Rvmxu$+=q$7?l_ss6g&L!"
    "xCVDSCCCqGU}hu1>`j|l#;H!9K0K2~6t>kHpRG|xDw53*(<kro!7^acd5mRsHrQ;9KIKNS4gNSQB}b=z6wCKF4IN;;awmY$#(qiq"
    "#Xk=Q56wJmH_XrI`a1xP*CDf+rC@yQ9xUL%4X!jk9rn$Vl`Uh6FD)^NDMvmqCu5#*hQC;M?gkATjbHV<YSnKb`u??y7A{4h`-Jws"
    "@}$*+jw{jOj<rVWwYF}QL-aFgp0|^3DGikrYxY)0sto}XR(4t3^u0|tmE`Om8J5iTQkY>Rl2OFY&Z10QPHys{$!UD-&F8i$u%>s-"
    "3{uhXUrAaHVwz|v49%xvsFM;cgOKYZFkKNhabKDGt&I$v^wEAs5>HI{%uEeL(spOkizRUu^iGz>mIW}9Qmu$AO(^~sO+%mbQJzkQ"
    "Y=4_4z1%JLOyb9JR5)e<LVXn3^<-pwKXU6B7fsKst=G)-AMSce9@Ve0pw4Q$1|;<!gx)E7E{1$(+oisxXLE}!OqdzeGn6SjOox?("
    "l&b<TMqJ2Jd(s|gU&8<j5i!$t`R%B4>cx7T0627N)@b)bu{kborJG{2^CiB`STslJgC-AO1JmSMbXIXc9r5<}Wq5?g$r=9--Uu_E"
    "^+P<<qNjs5f)o9BB%k~@FYW(}=f$R@^@^2E_+_5&i8Rt{X0<LwU+J{8iXkhPP1)|vCQiHG6>HQP=gi^;cjw-T^e-o)+UCG{%mF)0"
    "M3AZv8c}X6pnVZ5(+9mzk8l&#jKfT#nHI0!fw&ISdu*9B`SLhVXCXa}_v@il-H4x?ilUm%Y%9*nC12VS2B!Ylo<-RD60VXX&^Pp!"
    ";985$P2#W$56+?EdB+ukOpJFQ;BGt?7Vk-3pUJwsF<y6k2S{nV*qlOk69++@o!NMH3pw^{n<^sx0LiLWQnzF%%h-z>SIrnw-b`+s"
    "NOi4#XI}jLAe6jtg4c~hbU6wzAC<hiSU>pVkN*ph<wPm"
)
_PARENT_PATCHES = None
_GIT_PARENT_BLOBS = False


def _parent_patches():
    global _PARENT_PATCHES
    if _PARENT_PATCHES is None:
        _PARENT_PATCHES = json.loads(zlib.decompress(base64.b85decode(PARENT_PATCHES_B85)).decode('ascii'))
    return _PARENT_PATCHES


def _git_parent_blobs():
    global _GIT_PARENT_BLOBS
    if _GIT_PARENT_BLOBS is False:
        probe = subprocess.run(['git', 'cat-file', '-e', ACCEPTED + ':eng/blazor-package-resolver/tests/fixtures'],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if probe.returncode != 0:
            _GIT_PARENT_BLOBS = None
        else:
            raw_tar = subprocess.check_output(['git', 'archive', '--format=tar',
                                               ACCEPTED + ':eng/blazor-package-resolver/tests/fixtures'])
            blobs = {}
            with tarfile.open(fileobj=io.BytesIO(raw_tar), mode='r:') as tf:
                for member in tf.getmembers():
                    if member.isfile():
                        blobs[member.name] = tf.extractfile(member).read()
            _GIT_PARENT_BLOBS = blobs
    return _GIT_PARENT_BLOBS


def historical_parent_bytes(fixtures, name, allow_git=True):
    patches = _parent_patches()
    check(name in patches['pins'], 'Unknown historical parent path: ' + name)
    if name in patches['readmes']:
        reconstructed = patches['readmes'][name].encode('utf-8')
    elif name == 'cases.json':
        reconstructed = (fixtures / name).read_bytes().replace(b'"resolver_version": "1.1.0"', b'"resolver_version": "1.0.0"', 1)
    elif name in patches['cases']:
        doc = json.loads((fixtures / name).read_bytes())
        for case, (diff_top, diff_exp, removed_exp) in zip(doc['cases'], patches['cases'][name]):
            case.update(diff_top)
            for key in removed_exp:
                case['expected'].pop(key, None)
            case['expected'].update(diff_exp)
        reconstructed = (json.dumps(doc, indent=2, ensure_ascii=True) + '\n').encode('utf-8')
    else:
        reconstructed = (fixtures / name).read_bytes()
    check(sha(reconstructed) == patches['pins'][name], 'Corrupted historical parent baseline: ' + name)
    if allow_git:
        git_blobs = _git_parent_blobs()
        if git_blobs is not None:
            check(git_blobs.get(name) == reconstructed, 'Historical git object disagrees with pinned parent baseline: ' + name)
    return reconstructed


def lp03_declaration_delta(suite):
    """Named lp03-sbom-declarations-1.1.0: no fixture input or metadata changes."""
    for case in suite["cases"]:
        result = case["expected"]
        check(result["row_id"] == case["row_id"] == "LP-03" and
              result["resolver_id"] == "lp03-dependency-licenses" and result["resolver_version"] == "1.0.0",
              "Unexpected historical LP-03 identity")
        result["resolver_version"] = "1.1.0"
        result["evidence_contract"] = (
            "The caller designates the bound raw SBOM as the authoritative release-wide inventory; "
            "structural checks do not independently establish completeness or publication. "
            "Each included NuGet dependency is classified from its exact checked nupkg declaration "
            "using LP-01 policy 1.0.0 and SPDX 3.27.0. No ordinary grant, reviewer or owner approval "
            "is required. No legal sufficiency, notice compliance or build correspondence is established.")
        if case["case_id"] == "lp03-missing-package":
            continue
        branch, missing, required, next_category = (
            ("scope-missing", "The exact root and release-wide SBOM assessment binding is missing.", "assessment", "assessment-scope")
            if result["branch_id"] == "scope-missing" else
            ("input-invalid", "The supplied LP-03 assessment uses legacy schema 1; re-admit a schema-2 release-wide SBOM packet.",
             "supported-release-sbom-packet", "evidence-repair"))
        result.update(branch_id=branch, decision="escalated", applicability="unknown", finding=None,
                      missing_fact=missing, required_input=required, next_category=next_category)


def check(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def nuspec_namespace_version_delta(suite, row):
    """Only result versions change; historical fixture bytes and branches stay frozen."""
    versions = {"LP-01": ("lp01-license-policy", "1.0.0", "1.1.0"),
                "LP-03": ("lp03-dependency-licenses", "1.1.0", "1.2.0"),
                "PI-01": ("pi01-strong-name", "1.0.0", "1.1.0")}
    resolver, before, after = versions[row]
    for case in suite["cases"]:
        result = case["expected"]
        check(result["row_id"] == case["row_id"] == row and
              result["resolver_id"] == resolver and result["resolver_version"] == before,
              "Unexpected historical nuspec namespace result identity: " + row)
        result["resolver_version"] = after


def tooling_fixes_delta(suite):
    """Reviewed source-member/mixed-inventory/limitation result fields; no fixture changes."""
    trust = "npm archive hashes bind caller-designated bytes and do not authenticate publisher archives."
    for case in suite["cases"]:
        result = case["expected"]
        row = result["row_id"]
        if row == "LP-02":
            check(result["resolver_version"] == "1.1.0", "Unexpected LP-02 tooling delta")
            result["resolver_version"] = "1.2.0"
        elif row == "LP-03":
            check(result["resolver_version"] == "1.2.0", "Unexpected LP-03 tooling delta")
            result["resolver_version"] = "1.4.0"
            result["evidence_contract"] = result["evidence_contract"].replace(
                "Each included NuGet dependency is classified from its exact checked nupkg declaration ",
                "Each included dependency is classified from its exact checked nupkg or npm tarball declaration ") + " " + trust
            for key in ("finding", "missing_fact"):
                if result[key] is not None:
                    result[key] += " " + trust
        elif row == "LP-10":
            check(result["resolver_version"] == "1.0.0", "Unexpected LP-10 tooling delta")
            result["resolver_version"] = "1.1.0"
            if result["branch_id"] in ("unsupported-executable-content", "compiled-attribution-unverified",
                                      "text-code-attribution-unverified", "mixed-code-attribution-unverified"):
                result["missing_fact"] += (
                    " This package-only resolver accepts no source/provenance maps and performs no builds or transforms. "
                    "Retain the inventory for a separate attribution assessment against paragraph 29; no currently supported packet can verify these candidates.")
                result["required_input"] = "separate-attribution-assessment-outside-current-resolver"
                result["next_category"] = "assessment-limitation"
        else:
            check(False, "Unreviewed row in tooling delta")


def check_parent_file(name, before, after):
    """Admit only named row deltas, including nuspec-namespaces version-only results."""
    if before == after:
        return
    if name == "lp04/cases.json":
        from oracles.lp04_dlite_expectations import legacy_delta
        expected = json.loads(before)
        check(len(expected["cases"]) == 43, "Unexpected historical LP-04 inventory")
        legacy_delta(expected)
        reviewed = (json.dumps(expected, indent=2, ensure_ascii=True) + "\n").encode()
        check(after == reviewed, "Unreviewed LP-04 change outside D-lite expected results: " + name)
        return
    if name == "cases.json":
        expected = json.loads(before)
        check(len(expected["cases"]) == 2 and
              expected["cases"][0]["case_id"] == "synthetic-package" and
              expected["cases"][0]["row_id"] == expected["cases"][0]["expected"]["row_id"] == "LP-01" and
              expected["cases"][0]["expected"]["resolver_id"] == "lp01-license-policy" and
              expected["cases"][0]["expected"]["resolver_version"] == "1.0.0",
              "Unexpected historical foundation LP-01 identity")
        reviewed = before.replace(b'"resolver_version": "1.0.0"', b'"resolver_version": "1.1.0"', 1)
        check(after == reviewed, "Unreviewed foundation change outside nuspec-namespaces version delta")
        return
    if name in LP03_LEGACY_PINS:
        check(sha(before) == LP03_LEGACY_PINS[name], "Unexpected historical LP-03 bytes")
        expected = json.loads(before)
        lp03_declaration_delta(expected)
        nuspec_namespace_version_delta(expected, "LP-03")
        tooling_fixes_delta(expected)
        reviewed = (json.dumps(expected, indent=2, ensure_ascii=True) + "\n").encode()
        check(after == reviewed, "Unreviewed LP-03 change outside lp03-sbom-declarations-1.1.0: " + name)
        return
    if name in ("lp10/cases.json", "lp10/acceptance.json"):
        expected = json.loads(before)
        tooling_fixes_delta(expected)
        reviewed = (json.dumps(expected, indent=2, ensure_ascii=True) + "\n").encode()
        check(after == reviewed, "Unreviewed LP-10 change outside tooling limitation delta")
        return
    if name in ("lp01/cases.json", "lp01/acceptance.json"):
        expected = json.loads(before)
        changed = 0
        for case in expected["cases"]:
            result = case["expected"]
            if result["branch_id"] != "approved-non-copyleft":
                continue
            check(result["row_id"] == case["row_id"] == "LP-01" and
                  result["resolver_id"] == "lp01-license-policy" and
                  result["resolver_version"] == "1.0.0" and
                  all(result[key] == value for key, value in LP01_APPROVED_BEFORE.items()),
                  "Unexpected historical LP-01 approved result")
            result.update(LP01_APPROVED_VERIFIED)
            changed += 1
        check(changed == (23 if name == "lp01/cases.json" else 2),
              "Unexpected historical LP-01 approved inventory")
        nuspec_namespace_version_delta(expected, "LP-01")
        reviewed = (json.dumps(expected, indent=2, ensure_ascii=True) + "\n").encode()
        check(after == reviewed, "Unreviewed LP-01 change outside approved declaration delta: " + name)
        return
    if name in ("pi01/cases.json", "pi01/acceptance.json"):
        expected = json.loads(before)
        nuspec_namespace_version_delta(expected, "PI-01")
        reviewed = (json.dumps(expected, indent=2, ensure_ascii=True) + "\n").encode()
        check(after == reviewed, "Unreviewed PI-01 change outside nuspec-namespaces version delta: " + name)
        return
    if name == "lp01/README.md":
        check(sha(before) == "93eaab58da17a9c14d687159edaa84ad134406c1e5b38ab78e523fa89a8fe039" and
              sha(after) == "fb806cc03a44028f73974aead8e6c2630d289611b6a959369908e832da8c1ef2",
              "Unreviewed LP-01 contract change")
        return
    if name in ("lp02/cases.json", "lp02/acceptance.json"):
        expected = json.loads(before)
        check(len(expected["cases"]) == (33 if name == "lp02/cases.json" else 2),
              "Unexpected historical LP-02 inventory")
        previous_finding = next((case["expected"]["finding"] for case in expected["cases"]
                                 if case["expected"]["branch_id"] == "public-source-observed"), None)
        finding = (previous_finding.replace(
            "and retained files support a bounded mapping to the package's library source. ",
            "and the retained nonempty archive matches the declared repository/revision root. ").replace(
            "This establishes public source availability at the package-declared revision. ",
            "This establishes public source availability at the package-declared revision. "
            "The package declaration supplies that association; source relevance is not independently established. ")
            if previous_finding else None)
        for case in expected["cases"]:
            result = case["expected"]
            check(result["row_id"] == case["row_id"] == "LP-02" and
                  result["resolver_id"] == "lp02-public-source" and result["resolver_version"] == "1.0.0",
                  "Unexpected historical LP-02 identity")
            result["resolver_version"] = "1.1.0"
            if case["case_id"] in ("lp02-wrong-project-identity", "lp02-missing-implementation"):
                check(result["branch_id"] == "source-relevance-unestablished" and finding is not None,
                      "Unexpected historical LP-02 relevance result")
                result.update(branch_id="public-source-observed", decision="deterministic",
                              applicability="applicable", finding=finding, missing_fact=None,
                              required_input=None, next_category=None)
                case["rationale"] = case["rationale"].replace(
                    "must yield source-relevance-unestablished.", "must yield public-source-observed.")
            elif result["branch_id"] == "public-source-observed":
                check(result["finding"] == previous_finding, "Unexpected historical LP-02 positive finding")
                result["finding"] = finding
            elif result["branch_id"] == "source-relevance-unestablished":
                check(case["case_id"] == "lp02-missing-selected-file", "Unexpected selected-file case")
                result["missing_fact"] = "A selected supplemental source file is absent from the checked archive."
        reviewed = (json.dumps(expected, indent=2, ensure_ascii=True) + "\n").encode()
        tooling_fixes_delta(expected)
        reviewed = (json.dumps(expected, indent=2, ensure_ascii=True) + "\n").encode()
        check(after == reviewed, "Unreviewed LP-02 change outside public-availability/tooling delta: " + name)
        return
    if name == "lp02/README.md":
        check(sha(before) == "b46ea087b5a3700ff62c399aa2b5bb0d2ad6eb3115b5bdac04de508396044004" and
              sha(after) == "2b4a08adfd5d5f91832a27297a3d163f7290e26407fbdec709dd5da4a14b5663",
              "Unreviewed LP-02 contract change")
        return
    check(False, "Accepted parent mismatch: " + name)


def canonical(value):
    """Encode the frozen result writer's JSON shape, without executing any resolver."""
    if isinstance(value, dict):
        return "{" + ",".join(canonical(k) + ":" + canonical(v) for k, v in value.items()) + "}"
    if isinstance(value, list):
        return "[" + ",".join(canonical(item) for item in value) + "]"
    if isinstance(value, str):
        result = '"'
        escapes = {'\\': '\\\\', '\n': '\\n', '\r': '\\r', '\t': '\\t', '\b': '\\b', '\f': '\\f'}
        for char in value:
            if char in escapes:
                result += escapes[char]
            elif 0x20 <= ord(char) < 0x7f and char not in "\"&'+<>`":
                result += char
            else:
                raw = char.encode("utf-16-be", errors="surrogatepass")
                result += "".join("\\u" + raw[i:i + 2].hex().upper() for i in range(0, len(raw), 2))
        return result + '"'
    return json.dumps(value, separators=(",", ":"), allow_nan=False)


def safe(value):
    return (isinstance(value, str) and len(value) <= 256
            and re.fullmatch(r"[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*", value)
            and all(part not in (".", "..") for part in value.split("/")))


def load(name):
    path = STORE / name
    check(path.stat().st_size <= 8 * 1024 * 1024, "Recipe document limit")
    return json.loads(path.read_bytes())


def materialize(destination):
    destination = Path(destination).resolve()
    check(not destination.exists(), "Materialization requires a new isolated root")
    lock = load("lock.json")
    check(set(lock) == {"schema", "parent", "files", "row_outputs", "recipes_sha256",
                       "expectations_sha256", "bank_sha256"}, "Unknown lock fields")
    check(lock["schema"] == "resolver-corpus/1" and lock["parent"] == ACCEPTED, "Unsupported corpus")
    for name, field in (("recipes.json", "recipes_sha256"), ("expectations.json", "expectations_sha256"),
                        ("chunks.bin", "bank_sha256")):
        check(sha((STORE / name).read_bytes()) == lock[field], "Changed recipe store: " + name)
    recipes = load("recipes.json")
    expectations = load("expectations.json")
    bank = (STORE / "chunks.bin").read_bytes()
    check(len(bank) <= 16 * 1024 * 1024 and len(lock["files"]) <= 2000, "Corpus resource limit")
    actual_recipes = {}
    pins = {name: (length, digest) for name, length, digest in lock["files"]}
    check(len(pins) == len(lock["files"]) and all(
        safe(name) and type(length) is int and 0 <= length <= 8 * 1024 * 1024 and
        isinstance(digest, str) and re.fullmatch(r"[a-f0-9]{64}", digest)
        for name, (length, digest) in pins.items()), "Invalid output pins")
    for source in (recipes, expectations):
        check(set(source) == {"strings", "nodes", "files"}, "Unknown recipe fields")
        strings, nodes = source["strings"], source["nodes"]
        check(len(strings) <= 100000 and len(nodes) <= 100000, "Recipe node limit")
        built = []
        for index, node in enumerate(nodes):
            kind, value = node
            def child(i):
                check(type(i) is int and 0 <= i < index, "Forward/cyclic JSON recipe")
                return built[i]
            if kind == "s":
                check(type(value) is int and 0 <= value < len(strings), "Invalid string reference")
                result = strings[value]
            elif kind == "o":
                check(len({key for key, _ in value}) == len(value), "Duplicate recipe key")
                result = {strings[key]: child(item) for key, item in value}
            elif kind == "a":
                result = [child(item) for item in value]
            elif kind == "v":
                check(value is None or type(value) in (bool, int), "Unsupported JSON scalar")
                result = value
            else:
                raise ValueError("Unsupported JSON recipe")
            built.append(result)
        for name, recipe in source["files"].items():
            check(safe(name) and name not in actual_recipes, "Duplicate/unsafe output")
            check(name in pins, "Extra output")
            kind, value = recipe
            if kind in ("j", "u"):
                check(type(value) is int and 0 <= value < len(built), "Invalid JSON root")
                chunks, total = [], 1
                for part in json.JSONEncoder(indent=2, ensure_ascii=kind == "j").iterencode(built[value]):
                    raw = part.encode()
                    total += len(raw)
                    check(total <= pins[name][0], "Rendered JSON resource limit")
                    chunks.append(raw)
                data = b"".join(chunks) + b"\n"
            elif kind == "b":
                chunks, total = [], 0
                for offset, length in value:
                    check(type(offset) is int and type(length) is int and
                          0 <= offset <= len(bank) and 0 < length <= len(bank) - offset,
                          "Invalid raw byte slice")
                    total += length
                    check(total <= pins[name][0], "Raw composition resource limit")
                    chunks.append(bank[offset:offset + length])
                data = b"".join(chunks)
            else:
                raise ValueError("Unsupported output recipe")
            actual_recipes[name] = data
    check(len(pins) == len(lock["files"]) and set(pins) == set(actual_recipes), "Missing/extra outputs")
    check(sum(len(data) for data in actual_recipes.values()) <= 64 * 1024 * 1024, "Total byte limit")
    for name, data in actual_recipes.items():
        length, digest = pins[name]
        check(len(data) == length and sha(data) == digest, "Output mismatch: " + name)
    for name, digest in lock["row_outputs"].items():
        suite = json.loads(actual_recipes[name])
        output = {"schema_version": 1, "cases": [
            {"case_id": item["case_id"], "result": item["expected"]} for item in suite["cases"]]}
        check(sha((canonical(output) + "\n").encode()) == digest,
              "Canonical row output changed: " + name)
    destination.mkdir(parents=True)
    try:
        for name, data in actual_recipes.items():
            target = destination / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        check({p.relative_to(destination).as_posix() for p in destination.rglob("*")
               if p.is_file()} == set(pins), "Materialized output set differs")
    except BaseException:
        shutil.rmtree(destination)
        raise
    return lock


def temporary():
    parent = Path(tempfile.mkdtemp(prefix="resolver-corpus-"))
    atexit.register(shutil.rmtree, parent)
    directory = parent / "fixtures"
    materialize(directory)
    return parent, directory


def oracle(name, extra_args=()):
    parent, fixtures = temporary()
    for path in (HERE / "oracles").glob("*.py"):
        shutil.copyfile(path, parent / path.name)
    sys.path.insert(0, str(parent))
    if name == "pi01_expectations.py":
        print("PI-01: historical correlated conformance checker; independent claim is limited "
              "to locked bytes and construction facts, not semantic/cryptographic validation.")
    sys.argv = [str(parent / name), *extra_args]
    runpy.run_path(str(parent / name), run_name="__main__")


ORACLE_FILES = {
    "lp01": "lp01_expectations.py",
    "lp02": "lp02_expectations.py",
    "lp03": "lp03_sbom_expectations.py",
    "lp04": "lp04_dlite_expectations.py",
    "lp05": "lp05_expectations.py",
    "lp06": "lp06_expectations.py",
    "lp07": "lp07_expectations.py",
    "lp08": "lp08_expectations.py",
    "lp09": "lp09_expectations.py",
    "lp10": "lp10_expectations.py",
    "pi01": "pi01_expectations.py",
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("materialize")
    create.add_argument("--output", required=True)
    verify = sub.add_parser("verify")
    verify.add_argument("--parent", action="store_true")
    replay = sub.add_parser("replay")
    replay.add_argument("row", choices=["foundation", *["lp%02d" % i for i in range(1, 11)], "pi01"])
    oracle_cmd = sub.add_parser("oracle")
    oracle_cmd.add_argument("row", choices=list(ORACLE_FILES))
    oracle_cmd.add_argument("args", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.command == "materialize":
        materialize(args.output)
        return
    if args.command == "oracle":
        oracle(ORACLE_FILES[args.row], args.args)
        return
    parent, fixtures = temporary()
    if args.command == "verify":
        lock = load("lock.json")
        if args.parent:
            check(set(_parent_patches()["pins"]) == {name for name, _, _ in lock["files"]},
                  "Historical parent pin set differs from locked corpus")
            for name, length, digest in lock["files"]:
                old = historical_parent_bytes(fixtures, name)
                check_parent_file(name, old, (fixtures / name).read_bytes())
        print("Corpus verified:", len(lock["files"]), "exact paths;",
              sum(pin[1] for pin in lock["files"]), "bytes; locked canonical outputs verified"
              " (only named LP-01 declaration, LP-02 public-availability, lp03-sbom-declarations-1.1.0"
              ", nuspec-namespaces version-only and LP-04 D-lite result-only deltas are allowed against parent).")
    else:
        manifest = fixtures / ("cases.json" if args.row == "foundation" else args.row + "/cases.json")
        subprocess.run(["dotnet", "run", "--no-restore", "--project",
                        str(HERE.parent / "BlazorPackageResolver.csproj"), "--",
                        "replay", str(manifest)], check=True)


if __name__ == "__main__":
    main()
