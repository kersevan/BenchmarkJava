import analyzeCodeQL
import analyzeSnyk
import analyzeSemgrep
import Classes
from pprint import pprint
from jinja2 import FileSystemLoader, Environment
import json
import yaml


def createMergedResultsSarifFile(rules, results, template, outputFileName):
    file_loader = FileSystemLoader('templates')
    env = Environment(loader=file_loader)
    jinja2Template = env.get_template(template)

    output = jinja2Template.render(rules=rules, results=results)

    # use yaml to clean json - remove excess commas, then turn back to json
    outputJson = json.dumps(yaml.safe_load(output))
    outputJson = json.loads(outputJson)

    # change fields for benchmark to distinguish between tools
    outputJson["runs"][0]["tool"]["driver"]["name"] = outputFileName.split("/")[-1]
    outputJson["runs"][0]["tool"]["driver"]["semanticVersion"] = outputFileName.split("/")[-1]

    outputFile = open(outputFileName, "w+")
    outputFile.write(json.dumps(outputJson, indent=1))

def mergeCodeQLwithSnykByLocation(codeqlFileName, snykFileName, jinja2TemplateFileName, outputFileName):
    codeqlResults = analyzeCodeQL.extractResults(codeqlFileName)
    snykResults = analyzeSnyk.extractResults(snykFileName)
    codeqlRules = analyzeCodeQL.extractRules(codeqlFileName)
    snykRules = analyzeSnyk.extractRules(snykFileName)
    mergedResults, mergedRules = [], []

    for codeqlElement in codeqlResults:
        codeqlCwes = codeqlElement.cwes
        codeqlLocation = codeqlElement.location

        for snykElement in snykResults:
            # if snykElement.containsCwe(codeqlCwes):
            snykLocation = snykElement.location
            if codeqlElement.containsLocation(snykLocation):
                mergedResults.append(codeqlElement)

    createMergedResultsSarifFile(codeqlRules, mergedResults, jinja2TemplateFileName, outputFileName)

def mergeCodeQLwithSnykAdvanced(codeqlFileName, snykFileName, jinja2TemplateFileName, outputFileName):
    codeqlResults = analyzeCodeQL.extractResults(codeqlFileName)
    snykResults = analyzeSnyk.extractResults(snykFileName)
    codeqlRules = analyzeCodeQL.extractRules(codeqlFileName)
    snykRules = analyzeSnyk.extractRules(snykFileName)
    mergedResults, mergedRules = [], []

    for codeqlElement in codeqlResults:
        codeqlCwes = codeqlElement.cwes
        codeqlLocation = codeqlElement.location

        for snykElement in snykResults:
            # if snykElement.containsCwe(codeqlCwes):
            snykLocation = snykElement.location
            if codeqlElement.containsLocation(snykLocation):
                mergedResults.append(codeqlElement)

    createMergedResultsSarifFile(codeqlRules, mergedResults, jinja2TemplateFileName, outputFileName)

def mergeCodeQLwithSnyk(codeqlFileName, snykFileName, jinja2TemplateFileName, outputFileName):
    codeqlResults = analyzeCodeQL.extractResults(codeqlFileName)
    snykResults = analyzeSnyk.extractResults(snykFileName)
    codeqlRules = analyzeCodeQL.extractRules(codeqlFileName)
    snykRules = analyzeSnyk.extractRules(snykFileName)

    createMergedResultsSarifFile(codeqlRules + snykRules, codeqlResults + snykResults, jinja2TemplateFileName, outputFileName)

def mergeSemgrepWithCodeQL(semgrepFileName, codeqlFileName, jinja2TemplateFileName, outputFileName):
    codeqlResults = analyzeCodeQL.extractResults(codeqlFileName)
    semgrepResults = analyzeSemgrep.extractResults(semgrepFileName)
    codeqlRules = analyzeCodeQL.extractRules(codeqlFileName)
    semgrepRules = analyzeSemgrep.extractRules(semgrepFileName)

    createMergedResultsSarifFile(semgrepRules + codeqlRules, semgrepResults + codeqlResults, jinja2TemplateFileName, outputFileName)

def mergeSemgrepWithCodeQLPrecisionHigh(semgrepFileName, codeqlFileName, jinja2TemplateFileName, outputFileName):
    codeqlResults = analyzeCodeQL.extractResults(codeqlFileName)
    semgrepResults = analyzeSemgrep.extractResults(semgrepFileName)
    codeqlRules = analyzeCodeQL.extractRules(codeqlFileName)
    semgrepRules = analyzeSemgrep.extractRules(semgrepFileName)

    mergedResults, mergedRules = [], codeqlRules + semgrepRules

    highPrecisionRules = {}

    for rule in mergedRules:
        pprint(rule.precision)
        # pprint(vars(rule))
        if rule.precision == "HIGH":
            highPrecisionRules[rule.ruleId] = "HIGH"
        if rule.precision == "MEDIUM":
            highPrecisionRules[rule.ruleId] = "MEDIUM"

    for element in codeqlResults + semgrepResults:
        if element.ruleId in highPrecisionRules:
            mergedResults.append(element)
            continue
                
    createMergedResultsSarifFile(semgrepRules + codeqlRules, mergedResults, jinja2TemplateFileName, outputFileName)

def mergeSemgrepWithCodeQLAdvanced(semgrepFileName, codeqlFileName, jinja2TemplateFileName, outputFileName):
    codeqlResults = analyzeCodeQL.extractResults(codeqlFileName)
    semgrepResults = analyzeSemgrep.extractResults(semgrepFileName)
    codeqlRules = analyzeCodeQL.extractRules(codeqlFileName)
    semgrepRules = analyzeSemgrep.extractRules(semgrepFileName)

    mergedResults, mergedRules = [], codeqlRules + semgrepRules

    highPrecisionRules = {}

    for rule in mergedRules:
        pprint(rule.precision)
        # pprint(vars(rule))
        if rule.precision == "HIGH":
            highPrecisionRules[rule.ruleId] = "HIGH"
        if rule.precision == "MEDIUM":
            highPrecisionRules[rule.ruleId] = "MEDIUM"

    for element in codeqlResults + semgrepResults:
        if element.ruleId in highPrecisionRules:
            mergedResults.append(element)
            continue

                
    createMergedResultsSarifFile(mergedRules, mergedResults, jinja2TemplateFileName, outputFileName)

def mergeSemgrepWithCodeQLWithSnyk(semgrepFileName, codeqlFileName, snykFileName, jinja2TemplateFileName, outputFileName):
    codeqlResults = analyzeCodeQL.extractResults(codeqlFileName)
    semgrepResults = analyzeSemgrep.extractResults(semgrepFileName)
    snykResults = analyzeSnyk.extractResults(snykFileName)
    codeqlRules = analyzeCodeQL.extractRules(codeqlFileName)
    semgrepRules = analyzeSemgrep.extractRules(semgrepFileName)
    snykRules = analyzeSnyk.extractRules(snykFileName)

    mergedResults, mergedRules = codeqlResults + semgrepResults + snykResults, codeqlRules + semgrepRules + snykRules                
    createMergedResultsSarifFile(mergedRules, mergedResults, jinja2TemplateFileName, outputFileName)

def mergeSemgrepWithCodeQLWithSnykAdvanced(semgrepFileName, codeqlFileName, snykFileName, jinja2TemplateFileName, outputFileName):
    codeqlResults = analyzeCodeQL.extractResults(codeqlFileName)
    semgrepResults = analyzeSemgrep.extractResults(semgrepFileName)
    snykResults = analyzeSnyk.extractResults(snykFileName)
    codeqlRules = analyzeCodeQL.extractRules(codeqlFileName)
    semgrepRules = analyzeSemgrep.extractRules(semgrepFileName)
    snykRules = analyzeSnyk.extractRules(snykFileName)

    mergedResults, mergedRules = [], codeqlRules + semgrepRules + snykRules
    highPrecisionRules = {}

    for rule in codeqlRules + semgrepRules:
        # pprint(rule.precision)
        # pprint(vars(rule))
        if rule.precision == "HIGH":
            highPrecisionRules[rule.ruleId] = "HIGH"
        # if rule.precision == "MEDIUM":
        #     highPrecisionRules[rule.ruleId] = "MEDIUM"

    allResults = codeqlResults + semgrepResults + snykResults

    seenOnce = set()
    seenTwice = set()
    resultsAppearingTwice = []
    resultsAppearingTrice = []

    for result in allResults:
        if result.ruleId in highPrecisionRules:
            resultsAppearingTwice.append(result)
            continue
        location = f"uri: {result.location.uri}"
        print(location)
        # location = f"uri: {result.location.uri}, startLine: {result.location.startLine}"
        # print(location)
        if location in seenOnce:
            resultsAppearingTwice.append(result)
            if location in seenTwice:
                resultsAppearingTrice.append(result)
            else:
                seenTwice.add(location)
        else:
            seenOnce.add(location)


                
    createMergedResultsSarifFile(mergedRules, resultsAppearingTwice, jinja2TemplateFileName, outputFileName)

def mergeSemgrepWithCodeQLWithSnykByHighPrecision(semgrepFileName, codeqlFileName, snykFileName, jinja2TemplateFileName, outputFileName):
    codeqlResults = analyzeCodeQL.extractResults(codeqlFileName)
    semgrepResults = analyzeSemgrep.extractResults(semgrepFileName)
    snykResults = analyzeSnyk.extractResults(snykFileName)
    codeqlRules = analyzeCodeQL.extractRules(codeqlFileName)
    semgrepRules = analyzeSemgrep.extractRules(semgrepFileName)
    snykRules = analyzeSnyk.extractRules(snykFileName)

    mergedResults, mergedRules = [], codeqlRules + semgrepRules + snykRules
    highPrecisionRules = {}

    for rule in codeqlRules + semgrepRules:
        # pprint(rule.precision)
        # pprint(vars(rule))
        if rule.precision == "HIGH":
            highPrecisionRules[rule.ruleId] = "HIGH"

    allResults = codeqlResults + semgrepResults + snykResults

    seenOnce = set()
    seenTwice = set()
    resultsAppearingTwice = []
    resultsAppearingTrice = []

    for result in allResults:
        if result.ruleId in highPrecisionRules:
            resultsAppearingTwice.append(result)
            continue
        location = f"uri: {result.location.uri}, startLine: {result.location.startLine}"
        print(location)
        if location in seenOnce:
            resultsAppearingTwice.append(result)
            if location in seenTwice:
                resultsAppearingTrice.append(result)
            else:
                seenTwice.add(location)
        else:
            seenOnce.add(location)


                
    createMergedResultsSarifFile(mergedRules, resultsAppearingTwice, jinja2TemplateFileName, outputFileName)

def mergeSemgrepWithCodeQLWithSnykByCategories(semgrepFileName, codeqlFileName, snykFileName, jinja2TemplateFileName, outputFileName):
    codeqlResults = analyzeCodeQL.extractResults(codeqlFileName)
    semgrepResults = analyzeSemgrep.extractResults(semgrepFileName)
    snykResults = analyzeSnyk.extractResults(snykFileName)
    codeqlRules = analyzeCodeQL.extractRules(codeqlFileName)
    semgrepRules = analyzeSemgrep.extractRules(semgrepFileName)
    snykRules = analyzeSnyk.extractRules(snykFileName)

    mergedRules, mergedResults = codeqlRules + semgrepRules + snykRules, []
    allResults = codeqlResults + semgrepResults + snykResults
    allRules = codeqlRules + semgrepRules + snykRules
    ruleIds= []

    # switch = {
    #     '22' : 'pathtraver',
    #     '78' : 'cmdi',
    #     '79' : 'xss',
    #     '89' : 'sqli',
    #     '90' : 'ldapi',
    #     '327' : 'crypto',
    #     '328' : 'hash',
    #     '330' : 'weakrand',
    #     '501' : 'trustbound',
    #     '614' : 'securecookie',
    #     '643' : 'xpathi',
    # }

    # for rule in codeqlRules:
    #     print(rule.categories)
    #     print(rule.cwes)
    #     if "securecookie" in rule.categories:
    #         print(rule.ruleId)
    #         ruleIds.append(rule.ruleId)
    #     if "xss" in rule.categories:
    #         print(rule.ruleId)
    #         ruleIds.append(rule.ruleId)
    #     if "sqli" in rule.categories or "ldapi" in rule.categories or "pathtraver" in rule.categories:
    #         print(rule.ruleId)
    #         ruleIds.append(rule.ruleId)
    # for result in codeqlResults:
    #     if result.ruleId in ruleIds:
    #         mergedResults.append(result)

    # ruleIds= []

    # for rule in semgrepRules:
    #     if "weakrand" in rule.categories:
    #         ruleIds.append(rule.ruleId)
    #     if "crypto" in rule.categories:
    #         ruleIds.append(rule.ruleId)
    #     if "hash" in rule.categories:
    #         ruleIds.append(rule.ruleId)
    # for result in semgrepResults:    
    #     if result.ruleId in ruleIds:
    #         mergedResults.append(result)

    ruleIds = []
    for rule in allRules:
        if "xpathi" in rule.categories or "pathtraver" in rule.categories or "cmdi" in rule.categories or "sqli" in rule.categories or "ldapi" in rule.categories: 
            ruleIds.append(rule.ruleId)

    seen = set()
    resultsAppearingTwice = []

    for result in allResults:
        if result.ruleId in ruleIds:
            location = f"uri: {result.location.uri}, startLine: {result.location.startLine}"
            if location in seen:
                resultsAppearingTwice.append(result)
            else:
                seen.add(location)
    mergedResults += resultsAppearingTwice


    createMergedResultsSarifFile(mergedRules, mergedResults, jinja2TemplateFileName, outputFileName)

# COMPARE:
# 0. all results of different tools merged
#     - does removing duplicates help?
# 1. all results with precision HIGH
# 2. all results that appear in results of 2 different tools
# 3. all results that appear in results of 3 different tools
# 4. na podlagi expectedresults-1.2.csv pridobi TP, TN ...
#   - če naredim to lahko tudi SARD
