import random
import string


class VBSObfuscator:
	def __init__(self):
		pass
    
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
			return f"{(range+char)!s}-{range!s}"
		if exp == 1:
			return f"{(char-range)!s}+{range!s}"
		if exp == 2:
			return f"{(char*range)!s}/{range!s}"

	def obfu(self, body):
		encBody = ""
		for i in range(0, len(body)):
			if not encBody:
				encBody += self.expr(ord(body[i]))
			else:
				encBody += f"*{self.expr(ord(body[i]))}"
		return encBody
	
	def generator(self, vbs_content=None):
		#Splitter is set to be the "*" symbol,
		#since we are not using it in obfuscation
		splitter = str(chr(42))

		#Random function names
		NUM_OF_CHARS = random.randrange(5, 60)
		pld = "".join(random.choice(string.ascii_uppercase + string.ascii_lowercase) for _ in range(NUM_OF_CHARS))
		array = "".join(random.choice(string.ascii_uppercase + string.ascii_lowercase) for _ in range(NUM_OF_CHARS))
		temp = "".join(random.choice(string.ascii_uppercase + string.ascii_lowercase) for _ in range(NUM_OF_CHARS))
		x = "".join(random.choice(string.ascii_uppercase + string.ascii_lowercase) for _ in range(NUM_OF_CHARS))

		#Random Sub names
		subOne = "".join(random.choice(string.ascii_uppercase + string.ascii_lowercase) for _ in range(NUM_OF_CHARS))
		subTwo = "".join(random.choice(string.ascii_uppercase + string.ascii_lowercase) for _ in range(NUM_OF_CHARS))

		#Write to destination file
		obfuscated_file = "{0}\n{1}\n{2}\n{3}\n{4}\n{5}\n{6}\n{7}\n{8}\n{9}\n{10}\n{11}\n{12}\n".format(
			self.randCapitalization(f"Dim {pld}, {array}, {temp}"),
			self.randCapitalization(f"Sub {subOne}"),
			f"{self.randCapitalization(f"{pld} = ")}{chr(34)}{self.obfu(vbs_content)}{chr(34)}",
			f"{self.randCapitalization(f"{array} = Split({pld}, chr(eval(")}{self.obfu(splitter)})))",
			self.randCapitalization(f"for each {x} in {array}"),
			f"{self.randCapitalization(f"{temp} = {temp} & chr(eval({x}")}))",
			self.randCapitalization("next"),
			self.randCapitalization(subTwo),
			self.randCapitalization("End Sub"),
			self.randCapitalization(f"Sub {subTwo}"),
			f"{self.randCapitalization(f"eval(execute({temp}")}))",
			self.randCapitalization("End Sub"),
			self.randCapitalization(subOne)
		)

		return obfuscated_file