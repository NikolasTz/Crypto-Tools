CC = gcc
DBUG = -g
CCFLAGS = -O2 -Wall -pedantic
OBJFILES = main.o rsa.o utils.o

TARGET = rsa


all: $(TARGET)

$(TARGET): $(OBJFILES)
	$(CC) $(CCFLAGS) $(DBUG) -o $(TARGET) $(OBJFILES)

clean:
	rm -f $(TARGET) *.o
