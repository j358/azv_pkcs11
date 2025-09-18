# Display exported symbols:
#  nm -D azv-pkcs11.so | grep ' T '

SRC_DIR=./pkcs11/

CC= gcc
ARCH_FLAGS= -m64
CFLAGS= $(ARCH_FLAGS) -Wall -Wextra -Werror -O2 -I$(SRC_DIR)
LIBNAME=azv-pkcs11-x64.so

qa: config-qa all

series: config-series all

all: azv-pkcs11.o libazv.a
	$(CC) $(ARCH_FLAGS) -shared -o $(LIBNAME) \
	-Wl,-soname,$(LIBNAME) \
	-Wl,--version-script,$(SRC_DIR)/azv-pkcs11.version \
	azv-pkcs11.o \
	-I $(SRC_DIR) -L$(SRC_DIR) -lazv
	strip --strip-all $(LIBNAME)

azv-pkcs11.o: $(SRC_DIR)/azv-pkcs11.c $(SRC_DIR)/*.h libazv.a
	$(CC) $(CFLAGS) -fPIC -c $(SRC_DIR)/azv-pkcs11.c -I $(SRC_DIR) -L$(SRC_DIR) -lazv

libazv.a: go.mod azv_pkcs11.go lib/azvlib.go
	go build -buildmode=c-archive -o pkcs11/libazv.a

config-qa:
	echo package config > config/keyvault.go
	echo var KeyVaultName = \"MyTestVault-QA\" >> config/keyvault.go

config-series:
	echo package config > config/keyvault.go
	echo var KeyVaultName = \"MyTestVault\" >> config/keyvault.go

clean:
	-rm -f *.o

distclean: clean
	-rm -f *.so

deploy:
	@echo "Deploying $(LIBNAME) to /usr/lib/x86_64-linux-gnu/ossl-modules/"
# 	@cp libazv.so /usr/lib/
# 	@cp $(LIBNAME) /usr/lib/x86_64-linux-gnu/engines-3/
	@cp $(LIBNAME) /usr/lib/x86_64-linux-gnu/ossl-modules/
	@echo "Deployment complete."
