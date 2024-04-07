import random, string

class VBSObfuscator:
	def __init__(self):
		pass
		#self.__vbs_content = vbs_content
    
	def randCapitalization(self, characters):
		capicharacter = ""
		for character in characters:
			lowup = random.randrange(0,2)
			if lowup == 0:
				capicharacter += character.upper()
			if lowup == 1:
				capicharacter +=  character.lower()
		return capicharacter

	#Random mathematical expression decision
	def expr(self, char):
		range = random.randrange(100, 10001)
		exp = random.randrange(0, 3)
		if exp == 0:
			return str((range+char)) + "-" + str(range)
		if exp == 1:
			return str((char-range)) + "+" + str(range)
		if exp == 2:
			return str((char*range)) + "/" + str(range)

	def obfu(self, body):
		encBody = ""
		for i in range(0, len(body)):
			if encBody == "":
				encBody += self.expr(ord(body[i]))
			else:
				encBody += "*" + self.expr(ord(body[i]))
		return encBody
	
	def generator(self, vbs_content=None):
		#Splitter is set to be the "*" symbol,
		#since we are not using it in obfuscation
		splitter = str(chr(42))

		#Random function names
		NUM_OF_CHARS = random.randrange(5, 60)
		pld = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase) for _ in range(NUM_OF_CHARS))
		array = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase) for _ in range(NUM_OF_CHARS))
		temp = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase) for _ in range(NUM_OF_CHARS))
		x = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase) for _ in range(NUM_OF_CHARS))

		#Random Sub names
		subOne = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase) for _ in range(NUM_OF_CHARS))
		subTwo = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase) for _ in range(NUM_OF_CHARS))

		#Write to destination file
		obfuscated_file = ""
		obfuscated_file += self.randCapitalization("Dim " + pld + ", " + array + ", " + temp) + "\n"
		obfuscated_file += self.randCapitalization("Sub " + subOne) + "\n"
		obfuscated_file += self.randCapitalization(pld + " = ") + chr(34) + self.obfu(vbs_content) + chr(34) + "\n"
		obfuscated_file += self.randCapitalization(array + " = Split(" + pld + ", chr(eval(") + self.obfu(splitter) + ")))\n"
		obfuscated_file += self.randCapitalization("for each " + x + " in " + array) + "\n"
		obfuscated_file += self.randCapitalization(temp + " = " + temp + " & chr(eval(" + x) + "))\n"
		obfuscated_file += self.randCapitalization("next") + "\n"
		obfuscated_file += self.randCapitalization(subTwo) + "\n"
		obfuscated_file += self.randCapitalization("End Sub") + "\n"
		obfuscated_file += self.randCapitalization("Sub " + subTwo) + "\n"
		obfuscated_file += self.randCapitalization("eval(execute(" + temp) + "))\n"
		obfuscated_file += self.randCapitalization("End Sub") + "\n"
		obfuscated_file += self.randCapitalization(subOne) + "\n"

		return obfuscated_file