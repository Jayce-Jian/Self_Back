# CrackSleeve
- 将**cobaltstrike.jar**和**CrackSleeve.java**放一起
- 编译(`javac -encoding UTF-8 -classpath cobaltstrike.jar CrackSleeve.java`)
- 解密文件
- - ```bash
    Win：
        ## 用类文件的decode方法，解密jar包
        java -Dfile.encoding=UTF-8 -classpath "C:\cobaltstrike.jar";./ CrackSleeve decode

    Linux:
        ## 用类文件的decode方法，解密jar包
        java -classpath cobaltstrike.jar:. CrackSleeve decode
    ```
- 自定义16位字符串加密文件(`java -classpath cobaltstrike.jar;./ CrackSleeve encode CustomizeString`)
- 将解密后的sleeve文件夹替换jar包中的文件夹

# hex_to_java_array
**默认为cs4.4的key，可以替换十六进制key**

- `python3 hex_to_java_array.py 5e98194a01c6b48fa582a6a9fcbb92d6`
