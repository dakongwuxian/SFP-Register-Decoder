# SFP-Register-Decoder

这是一个光模块寄存器的解读工具，由xian wu编写，名称为“SFP-Reg-Decoder”。

简要说明：
1、将SFP A0h 和 A2h的寄存器内容粘贴到左侧的对应的窗口中，点击parse register按键，即可看到解析结果；
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

This is an interpretation tool for the optical module register, written by xian wu, and its name is "SFP-Reg-Decoder". 

Brief instructions:

1. Paste the contents of SFP A0h and A2h registers into the corresponding windows on the left side. Click the "Parse Register" button and you will see the parsing result.
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
