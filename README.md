BUZZER is a fuzzer for Bluetooth Host Stack. It is built upon panda and AFL++.

## Build
### Build BUZZER

```sh
# First, create project directory anywhere you want
export ProjectDir=/path/to/project
mkdir $ProjectDir

# Fetch BUZZER source code
cd $ProjectDir
git clone -b buzzer https://github.com/AminoACID123/panda
git clone https://github.com/AminoACID123/BlueBench

# Build BUZZER
cd $ProjectDir
cp panda/panda/scripts/install_ubuntu.sh .
./install_ubuntu.sh
```

### Build Fuzz Targets
#### Compile linux kernel
```sh
cd $ProjectDir/BlueBench/os/linux/kernel
wget https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.7.2.tar.xz
tar -xvf linux-6.7.2.tar.xz
# Compile kernel
cd linux-6.7.2.tar.xz
make defconfig
```
After that, edit `.config` file generated under the current directory:
-   Add `CONFIG_SWAP=n` (if `CONFIG_SWAP=y` exists, change it). 
-   Add `CONFIG_BT=y`.

Then, compile the kernel
```sh
make -j`nproc`
```
A few Bluetooth-related prompts will show up, just type `y` for all of them.

#### Prepare Init Ramfs
```sh
cd $ProjectDir/BlueBench/os/linux/initramfs
cp $ProjectDir/panda/build/x86_64-softmmu/buzzer_loader rootTemplate
./pack.sh
```

#### Build Target Programs (zephyr as an example)
Prepare Zephyr following instructions [here](https://docs.zephyrproject.org/latest/develop/getting_started/index.html). All Bluetooth examples are placed under `$ZephyrSource/samples/bluetooth`. Take `central_hr` as an example:
```sh
cd $ZephyrSource/samples/bluetooth/central_hr
west build -b native_posix_64 . -DCONFIG_ASAN=y -DCMAKE_C_FLAGS=-static-libasan
```
The built program is `zephyr.exe` under `$ZephyrSource/samples/bluetooth/central_hr/build/zephyr`

Then create target directory anywhere you want
```sh
export $TargetDir=/path/to/TargetDir
mkdir $TargetDir
cd $TargetDir
cp $ZephyrSource/samples/bluetooth/central_hr/build/zephyr/zephyr.exe .
cp $ProjectDir/panda/build/x86_64-softmmu/buzzer_preload.so .
```
As a last step, copy all shared libraries `zephyr.exe` depends on into `$TargetDir`. You can use `ldd zephyr.exe` command to see all relevant shared libraries.

## RUN
```sh
./buzzer-fuzz \
    -args "--bt-dev=hci0" \
    -m 512M  \
    -kernel $ProjectDir/BlueBench/os/linux/kernel/linux-6.7.2/arch/x86/boot/bzImage \
    -initrd $ProjectDir/BlueBench/os/linux/initramfs/init.cpio.gz \
    -append "nokaslr" \
    -chardev buzzer,id=bz -serial chardev:bz \
    -target-file zephyr.exe \
    -target-dir $TargetDir \
    -out out \
    -display none
```