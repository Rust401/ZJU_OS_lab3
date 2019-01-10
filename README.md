# Operating System(2018-2019Fall&Winter)LAB3

```shell
Project Name:   Add an Encrypt File System 
Student Name:   Hu.Zhaodong
Student ID  :   21714069
Major       :   Environmental Engineering
Email       :   zhaodonghu94@zju.edu.cn
phone       :   15700080428
Date        :   2018.9-2018.12
```
## TARGET
* Uderstand the princple of file system in OS.
* Uderstand the **VFS** and **ext2** in linux.
* Design and implement a encrypt file system.

## CONTENT
Add a new file system based on the current **ext2** file system with the function of encrypting the data block storing in the disk.
* **Clone** a file system based **ext2**.
* Modifiy the **magic number** of the new file system.
* Add a small tools to build a file system.
* Add the function to **encrypt** the data while write and **decrypt** the data while read. (The datas store in the disk are encrypt)

## DEVICE
```
CPU     :       intel core i7-4790k (4C8T) 4.6GHz
RAM     :       16G
OS      :       ubuntu-16.04.5-desktop-i386(Kernel 4.6.0)
gcc     :       4.8.5
thread  :       posix  
```

## STEP
**Remark:** These operations are based on the kernel version 4.6.0 and will use the root permission.
### 1. Add a file system named **myext2** based on the current **ext2**
We go to the directory `/usr/src/linux/fs/ext2` to find these files below are
belong to the **ext2** file system.
```
fs/ext2/acl.c
fs/ext2/acl.h
fs/ext2/balloc.c
fs/ext2/bitmap.c
fs/ext2/dir.c
fs/ext2/ext2.h
fs/ext2/file.c
......
include/linux/ext2_fs.h
```
We copy the source code to `/usr/src/linux/fs/myext2` and then put the head file to `/usr/src/linux/include/linux`. We do this operation in the shell:
```
#cd /usr/src/linux  /*kernel source code*/
#cd fs
#cp –R ext2 myext2  
#cd /usr/src/linux/fs/myext2
#mv ext2.h myext2.h 

#cd /lib/modules/$(uname -r)/build/include/linux
#cp ext2_fs.h myext2_fs.h 
#cd /lib/modules/$(uname -r)/build/include/asm-generic/bitops
#cp ext2-atomic.h myext2-atomic.h
#cp ext2-atomic-setbit.h myext2-atomic-setbit.h
```
After the clone of the source code we should change all the string `ext2` or `EXT2` to `myext2` and `MYEXT2`. We use the script below:
```sh
#!/bin/bash

SCRIPT=substitute.sh

for f in * 
do 
    if [ $f = $SCRIPT ]
    then
        echo "skip $f"
        continue
    fi

    echo -n "substitute ext2 to myext2 in $f..."
    cat $f | sed 's/ext2/myext2/g' > ${f}_tmp
    mv ${f}_tmp $f
    echo "done"

    echo -n "substitute EXT2 to MYEXT2 in $f..."
    cat $f | sed 's/EXT2/MYEXT2/g' > ${f}_tmp
    mv ${f}_tmp $f
    echo "done"

done

```
Save this script with the name `substitute.sh`. In the shell, Input:
```
#sudo bash substitute.sh
```
**Remark:** 
* Use the script only once.
* remove the `*.o` in the `fs/myext2` before run the script
* Attention to Capitalization

Use the subtitute function in our vim, substitue the `ext2`, `EXT2` to `myext2`, `MYEXT2` in the file below:
```
/lib/modules/$(uname -r)/build/include/linux/myext2_fs.h
/lib/modules/$(uname -r)/build/include/asm-generic/bitops/myext2-atomic.h
/lib/modules/$(uname -r)/build/include/asm-generic/bitops/myext2-atomic-setbit.h
```
**Remark:** About how to find the right place to add this code, just search the place the the **ext2-realted** file put themself. Then either blow them or upper them.
Add `#include <asm-generic/bitops/myext2-atomic.h>` in  
`/lib/modules/$(uname -r)/build/include/asm-generic/bitops.h`  
Add `#include <asm-generic/bitops/myext2-atomic-setbit.h>` in  
`/lib/modules/$(uname -r)/build/arch/x86/include/asm/bitops.h`  
Add `#define MYEXT2_SUPER_MAGIC 0xEF53` in  
`/lib/modules/$(uname -r)/build/include/uapi/linux/magic.h`

So the modified in source code are finished and we should modified the makefile:
```makefile
#
# Makefile for the linux myext2-filesystem routines.
#
obj-m := myext2.o 
myext2-y := balloc.o dir.o file.o ialloc.o inode.o \
	  ioctl.o namei.o super.o symlink.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd) 
default: 
	make -C $(KDIR) M=$(PWD) modules
clean:
    make -C $(KDIR) M=$(PWD) clean
```
Use the `make` to compile and use the `make clean` to remove the compiled file.  
After compile, insert this module and check if the filesystem is on running:
```sh
insmod myext2.ko
cat /proc/filesystems | grep myext2
```
Or we could also use the `lsmod | grep myext2` to check if our module is inserted successfully.  
Now if's the test time:  
```
#dd if=/dev/zero of=myfs bs=1M count=1
```
We use `dd` to copy a file from `/dev/zero` and the read and write bytes at one time is `1M` bytes, and the output file is `myfs`.  
**Remark:** the `/dev/zero` is a special file and it can supply infinite `NULL(0x00)` to the place you want. And now we get a file `myfs` with the size of 1M bytes and full of `0x00`.  
![Fig0](https://raw.githubusercontent.com/Rust401/ZJU_OS_lab3/master/image/fig0.png)
```
#/sbin/mkfs.ext2 myfs
```
We use the type ext2 to format the myfs. The operation include allocating **group table**, write **indode tables** and writing **superblock** and **filesystem accounting information**. We creat 1024 blocks with size of 1k and totally 128 inodes.  
![Fig1](https://raw.githubusercontent.com/Rust401/ZJU_OS_lab3/master/image/fig1.png)  
```
#mount -t myext2 -o loop ./myfs /mnt
#mount
```
A file include a `complete file system` can be link to a `loop device` and then we could mount this file just like a `disk`. So the command is just doing this things.  
For the `myfs` is a file with a complete file system, and the type of the file system is myext2. So we use `-t myext2` to declaration the type. And we use `-o loop` to declaration the operation is to find a `free loop device` and link. We mount our myext2 file system instance to the directory `/mnt`. And we could check the mount information:  
![Fig2](https://raw.githubusercontent.com/Rust401/ZJU_OS_lab3/master/image/fig2.png)  
Here I use another file named `newfs` formated with the ext2 to do the test and we found the mount is successful. Then we do umount this dude and do the test use the original file system `ext2`. And it's same as the `myext2` and the difference is just the file name and the `-t ext2`. We ommit the output.
```
#umount /mnt
#mount -t ext2 -o loop ./myfs /mnt
#mount
#umount /mnt
```
**Remark:** We use the `/sbin/mkfs.ext2` to use the `ext2` format to format the `zero file`. So the **magic number** in super block must be the magic number of ext2 file system. That is `0xEF53`. And we set the magic number of `myext2` file system is also `0xEF53`. So when mount happens the OS will check if the **magic number** in the super block  equal to `0xEF53` which is define in the `/lib/modules/$(uname -r)/build/include/uapi/linux/magic.h`. If not equal, the mount failed. So till now everthing works fine because both the two file system have the magic number `0xEF53`.

### 2. Modify the **magic number** of **myext2**
Based on the front work. We find the magic number of myext2 and change it to `0x6666`.
```
/lib/modules/$(uname -r)/build/include/uapi/linux/magic.h
- #define MYEXT2_SUPER_MAGIC	0xEF53
+ #define MYEXT2_SUPER_MAGIC	0x6666
```
We re-compile the `myext2` and do the next test.
We use the `changeMN.c` to change the magic number of myfs from `0xEF53` to `0x6666`. The content of the file is display below:
```c
#include <stdio.h>
main()
{
	int ret;
	FILE *fp_read;
	FILE *fp_write;
	unsigned char buf[2048];

	fp_read = fopen("./myfs", "rb");

	if (fp_read == NULL)
	{
		printf("open myfs failed!\n");
		return 1;
	}

	fp_write = fopen("./fs.new", "wb");

	if (fp_write == NULL)
	{
		printf("open fs.new failed!\n");
		return 2;
	}

	ret = fread(buf, sizeof(unsigned char), 2048, fp_read);

	printf("previous magic number is 0x%x%x\n", buf[0x438], buf[0x439]);

	buf[0x438] = 0x66;
	buf[0x439] = 0x66;

	fwrite(buf, sizeof(unsigned char), 2048, fp_write);

	printf("current magic number is 0x%x%x\n", buf[0x438], buf[0x439]);

	while (ret == 2048)
	{
		ret = fread(buf, sizeof(unsigned char), 2048, fp_read);
		fwrite(buf, sizeof(unsigned char), ret, fp_write);
	}

	if (ret < 2048 && feof(fp_read))
	{
		printf("change magic number ok!\n");
	}

	fclose(fp_read);
	fclose(fp_write);

	return 0;
}
```
The code here is easy, just read the data from `myfs` and change the value in the `buf[0x438]` and `buf[0x439]`. Write the data into a new file named `fs.new`.  
![fig3](https://raw.githubusercontent.com/Rust401/ZJU_OS_lab3/master/image/fig3.png)  
Here I modify the original c file and make the change could assign to specific fileName.  
Read from `myfs` and write to `newfs`. Now the magic number in myfs is `0xEF53` and the magic number in newfs is `0x6666`.

So at this time we could guess if we use the `-t myext2` to mount `myfs` we will failed because the magic number is not the `0x6666`. And we mount the `newfs` with the `-t ext2` we will also failed because of the magic number. Result is below:
```
fileName        MagicNumber     mountType       Target MN   result
myfs            0xEF53          ext2            0xEF53      success
myfs            0xEF53          myext2          0x6666      failed
newfs           0x6666          ext2            0xEF53      failed
newfs           0x6666          myext2          0x6666      success
```
The failed result are below:  
![fig4](https://raw.githubusercontent.com/Rust401/ZJU_OS_lab3/master/image/fig4.png)  
### 3. Modify the file system operation
We will trim the `mknod` of the `myext2`.  
We enter the `/usr/src/linux/fs/myext2/namei.c` and do the modify below:
```c
static int myext2_mknod (struct inode * dir, struct dentry *dentry, int mode, int rdev)
{
	printk(KERN_ERR “haha, mknod is not supported by myext2! you’ve been cheated!\n”);
	return -EPERM;
  /*
   commit the remain code
  */
}
```
Use the `make` to re-compile the myext2 and insert the module again then do the test below:
```shell
#mount –t myext2 –o loop ./fs.new /mnt
#cd /mnt
#mknod myfifo p
mknod: `myfifo': Operation not permitted
```  
![fig5](https://raw.githubusercontent.com/Rust401/ZJU_OS_lab3/master/image/fig5.png)  
Code is not hard here and we could find our trim get the effort.
### 4. Add a file system tool
We will make a script to build a file system here. The name is `myfs.myext2`.Just a scriptm, view the code:
```sh
#!/bin/bash

#detach the file in the loop2(if exist)  
/sbin/losetup -d /dev/loop2
#link the /dev/loop with the input file $S1
/sbin/losetup /dev/loop2 $1
#format the /dev/loop2 which is linked with the input file $S1 with the ext2
/sbin/mkfs.ext2 /dev/loop2
#copy a file from the zero device with the size of 2k bytes to tmpfs
dd if=/dev/loop2 of=./tmpfs bs=1k count=2
#change the Magic Number of fs.new with the help of tmpfs
./changeMN $1 ./tmpfs
#write back the 2k bytes to the head of loop device(change the magic number of myfs)
dd if=./fs.new of=/dev/loop2
#detach the myfs from /dev/loop2 
/sbin/losetup -d /dev/loop2
#remove the tmpfs
rm -f ./tmpfs
```
After the operation. Actually the script only do one thing. change the MN of `fs.new` and `myfs`. Actually we don't need to do that much. I think the below is better:
```sh
#!/bin/bash
#copy a new file full of zero with /dev/zero
dd if=/dev/zero of=myfs bs=1M count=1
#format the myfs with ext2
/sbin/mkfs.ext2 myfs
#change the magic number
./newChange myfs newfs
#mount the newfs with magic number 0x6666 to mnt
mount -t myext2 -o loop ./newfs /mnt
```
Ok the newfs is mounted in `/mnt`.
Just use:
```sh
sudo bash mkfs.myext2
```
the the file system is mounted in the `/mnt`.
### 5.Modify the read and write operation
Direct show my modified code here:
/usr/src/linux/fs/myext2/file.c
```c
#include <linux/uio.h>/*added at the top*/
/*
...
*/
#include "acl.h"
static ssize_t new_sync_read(struct file *filp, char __user *buf, size_t len, loff_t *ppos)
{
        struct iovec iov = { .iov_base = buf, .iov_len = len };
        struct kiocb kiocb;
        struct iov_iter iter;
        ssize_t ret;

        init_sync_kiocb(&kiocb, filp);
        kiocb.ki_pos = *ppos;
        iov_iter_init(&iter, READ, &iov, 1, len);

        ret = filp->f_op->read_iter(&kiocb, &iter);
        BUG_ON(ret == -EIOCBQUEUED);
        *ppos = kiocb.ki_pos;
        return ret;
}

static ssize_t new_sync_write(struct file *filp, const char __user *buf, size_t len, loff_t *ppos)
{
        struct iovec iov = { .iov_base = (void __user *)buf, .iov_len = len };
        struct kiocb kiocb;
        struct iov_iter iter;
        ssize_t ret;

        init_sync_kiocb(&kiocb, filp);
        kiocb.ki_pos = *ppos;
        iov_iter_init(&iter, WRITE, &iov, 1, len);

        ret = filp->f_op->write_iter(&kiocb, &iter);
        BUG_ON(ret == -EIOCBQUEUED);
        if (ret > 0)
                *ppos = kiocb.ki_pos;
        return ret;
}
static ssize_t new_sync_read_crypt(struct file *filp,char __user *buf, size_t len,loff_t *ppos)
{
        int i;
        char* mybuf=(char*)kmalloc(sizeof(char)*len,GFP_KERNEL);
        ssize_t ret=new_sync_read(filp,buf,len,ppos);
        copy_from_user(mybuf,buf,len);
        for(i=0;i<len;++i)mybuf[i]=(mybuf[i]-25+128)%128;
        copy_to_user(buf,mybuf,len);
        printk("haha decrypt %u\n",len);
        return ret;
}

static ssize_t new_sync_write_crypt(struct file *filp,const char __user *buf,size_t len, loff_t *ppos)
{
        int i;
        char* mybuf=(char*)kmalloc(sizeof(char)*len,GFP_KERNEL);
        copy_from_user(mybuf,buf,len);
        for(i=0;i<len;++i)mybuf[i]=(mybuf[i]+25)%128;
        copy_to_user(buf,mybuf,len);
        printk("haha encrypt %u\n",len);
        return new_sync_write(filp,buf,len,ppos);
}
/*
...
*/

const struct file_operations myext2_file_operations = {
        .read           = new_sync_read_crypt,
        .write          = new_sync_write_crypt,
        .llseek         = generic_file_llseek,
        .read_iter      = generic_file_read_iter,
        .write_iter     = generic_file_write_iter,
        .unlocked_ioctl = myext2_ioctl,
#ifdef CONFIG_COMPAT
        .compat_ioctl   = myext2_compat_ioctl,
#endif
        .mmap           = myext2_file_mmap,
        .open           = dquot_file_open,
        .release        = myext2_release_file,
        .fsync          = myext2_fsync,
        .splice_read    = generic_file_splice_read,
        .splice_write   = iter_file_splice_write,
};

const struct inode_operations myext2_file_inode_operations = {
#ifdef CONFIG_MYEXT2_FS_XATTR
        .setxattr       = generic_setxattr,
        .getxattr       = generic_getxattr,
        .listxattr      = myext2_listxattr,
        .removexattr    = generic_removexattr,
#endif
        .setattr        = myext2_setattr,
        .get_acl        = myext2_get_acl,
        .set_acl        = myext2_set_acl,
        .fiemap         = myext2_fiemap,
};
```
After the modified we use the `make` re-compile and use our script to mount the file system. And do the test below:
```sh
cd /mnt
echo "0123456789" >> test.txt
cat test.txt
cp test.txt /home/rust/Desktop
```
And then we copy the file use the gnome from `/mnt` to `/home/rust/Desktop`. The result are below:  
![fig6](https://raw.githubusercontent.com/Rust401/ZJU_OS_lab3/master/image/fig6.png)
![fig7](https://raw.githubusercontent.com/Rust401/ZJU_OS_lab3/master/image/fig7.png)  
**Remark:** There are some difference between the `cp` in shell and the `cpopy` in GUI in this test. The `cp` in the shell will read the data in the file first then write back to a file in the new location. So when we copy the file from our file system `myext2` which is mounted in `/mnt` to the other fs run on my ubuntu. We decrypt the data first then write back so the data store in the disk is not encrypted. So the read operation in the original file system with out the decrypt can show the original data. But the `copy` in the GUI has the different result maybe the copy is use the mmap instead of read. Says the `copy` in GUI needn't read the data first, they directly map the data. So use the original read operation will get the encrypt result.





