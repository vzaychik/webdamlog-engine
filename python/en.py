def enum(**named_values):
     return type('Enum', (), named_values)

Color = enum(RED='red', GREEN='green', BLUE='blue') 
ob = Color.RED
print ob

def printsomethng():
     if (1==0):
         print Color.RED
     else:
        print "failed"

if __name__ == "__main__":
	printsomethng()
