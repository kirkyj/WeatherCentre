import re

inFilename = "reg-test"
outFilename = "reg-test-out"

inputFile = open(inFilename, "r")
outputFile = open(outFilename, "w")
results = []


for line in inputFile:
    test = re.match("((.*.gov.)|(.*.sch.)|(.*.nhs.)|(.*.ac.))uk", line)
    if test:
        results.append(line)



print (results)

for domain in results:
    outputFile.write(domain)

inputFile.close()
outputFile.close()
