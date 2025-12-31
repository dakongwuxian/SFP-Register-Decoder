# SFP-Register-Decoder

SFP-Reg-Decoder 用户手册 - last edit on 2025.12.29 by xian wu

这是一个光模块寄存器的解读工具，名称为“SFP-Reg-Decoder”。

本软件由Xian Wu个人开发，为单一exe文件的GUI程序，可在windows系统上运行（如果要在其他操作系统上运行需要使用原代码重新打包），使用python 3.10和VS code的环境，借助了ChatGPT和AMAZON Q的帮助。

本软件为开源软件，如果想要商用请取得原作者许可，请联系dakongwuxian@gmail.com或xian.wu@ericsson.com。

简要说明：

1、将SFP A0h 和 A2h的寄存器内容粘贴到左侧的对应的窗口中（可以全部粘贴到A0h，格式可以是单独的AA FF……，也可以是8个hex连续的 AAAAAAAA FFFFFFFF……，对Ericsson radio的2中register dump的格式也可以直接解析），点击parse register按键，即可看到解析结果；

2、粘贴进去的内容需要是只包含十六进制的数字和字母的字符，不要0xAA的0x，只要AA，可以包含空格和换行符，A0h必须是128byte或者256byte，A2h必须是256byte；

3、解析后，可以用鼠标点击左侧窗口中的寄存器值，或者点击中间输出窗口中的任意内容，会在右侧出现对应byte的详细解释，同时会将左侧、中间对应的位置都标黄出来；

4、右侧窗口的上方有一个8bit的显示窗口，当你双击右侧的大窗口中的某个8bit的二进制数，该二进制数会被高亮，同时上方的8个bit窗口会对应为该二进制数；

5、当右侧有二进制数被高亮时，单机8bit窗口的任意一个bit，该bit即会翻转，同时右侧大窗口中的内容会对应修改；

6、如果在右侧大窗口中有高亮内容时，点击apply change按键，则会更新左侧、中间、右侧的寄存器内容。

注意：

1、该exe必须要跟 A0h_bits_explanation.txt 和 A2h_bits_explanation.txt 两个文件放在同一个文件夹，否则右侧窗口会没有内容可以显示。

2、这2个txt文件可以手动修改，修改后保存，重启exe即可生效，如果发现有相应的bit解释是错误的，可以直接自行修改。

可能存在潜在的错误，仅供参考，如果发现错误，请及时告知 xian.wu@ericsson.com 或 dakongwuxian@mail.com 。

欢迎提出意见及建议~

exe 文件的下载链接如下：

https://github.com/dakongwuxian/SFP-Register-Decoder/releases



SFP-Reg-Decoder User Manual

Last edited on December 29, 2025, by Xian Wu

SFP-Reg-Decoder is a tool designed for interpreting optical transceiver register data.

This software was developed independently by Xian Wu. It is a GUI application provided as a single .exe file compatible with Windows systems (repackaging the source code is required for other operating systems). The development environment utilized Python 3.10 and VS Code, with assistance from ChatGPT and Amazon Q.

This is open-source software. Please obtain permission from the original author for any commercial use. For inquiries, please contact dakongwuxian@gmail.com or xian.wu@ericsson.com.

Brief instructions:

1. "Paste the register contents of SFP A0h and A2h into the corresponding windows on the left. You can paste everything into the A0h window. Supported formats include individual hex bytes (e.g., AA FF...), continuous 8-byte hex strings (e.g., AAAAAAAA FFFFFFFF...), or direct register dumps from Ericsson radios. Click the 'Parse Register' button to view the analysis results."
2. The content to be pasted must consist only of hexadecimal numbers and letters. Do not include "0xAA" (0x), just "AA". It can contain spaces and line breaks. A0h must be 128 bytes or 256 bytes, and A2h must be 256 bytes.
3. After parsing, you can click the register value in the left window with the mouse, or click any content in the middle output window. A detailed explanation of the corresponding byte will appear on the right side, and the corresponding positions on the left and middle sides will be highlighted.
4. There is an 8-bit display window on the top of the right window. When you double-click an 8-bit binary number in the large window on the right, that binary number will be highlighted, and the 8-bit window above will correspond to that binary number.
5. When a binary number is highlighted on the right, click any bit in the 8-bit window, that bit will flip, and the content in the large window on the right will be correspondingly modified.
6. If there is highlighted content in the large window on the right, click the "Apply Change" button, and the register contents on the left, middle, and right will be updated. 


Note:
1. This exe file must be placed in the same folder as the two files A0h_bits_explanation.txt and A2h_bits_explanation.txt. Otherwise, the right window will have no content to display.
2. These two txt files can be manually modified. After modification, save them and restart the exe file for the changes to take effect. If you find that the corresponding bit explanations are incorrect, you can modify them directly yourself. 

There may be potential errors. This is for reference only. If any errors are found, please notify xian.wu@ericsson.com or dakongwuxian@mail.com promptly.

We welcome your comments and suggestions!

exe file could be download here:

https://github.com/dakongwuxian/SFP-Register-Decoder/releases
