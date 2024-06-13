"""
Dataset Collection Tool.
Author:		Seunghoon Woo (seunghoonwoo@korea.ac.kr)
Modified: 	~ing
Modify author: Heedong Yang (heedongy@korea.ac.kr)
"""

import os
import git
import shutil
import subprocess
import re
import tlsh
import concurrent.futures

"""GLOBALS"""

currentPath = "/hdd1/dataset_test"
gitCloneURLS = os.getcwd() + "/sampletest"  # Please change to the correct file (the "sample" file contains only 10 git-clone urls)
funcCodePath = currentPath + "/repo_funcCode/"
clonePath = currentPath + "/repo_src/"  # Default path
tagDatePath = currentPath + "/repo_date/"  # Default path
resultPath = currentPath + "/repo_functions/"  # Default path
ctagsPath = "/usr/local/bin/ctags"  # Ctags binary path (please specify your own ctags path)

# Generate directories
shouldMake = [clonePath, tagDatePath, resultPath]
for eachRepo in shouldMake:
    if not os.path.isdir(eachRepo):
        os.mkdir(eachRepo)


# Generate TLSH
def computeTlsh(string):
    string = str.encode(string)
    hs = tlsh.forcehash(string)
    return hs


def removeComment(string):
    # Code for removing C/C++ style comments. (Imported from VUDDY and ReDeBug.)
    # ref: https://github.com/squizz617/vuddy
    c_regex = re.compile(
        r'(?P<comment>//.*?$|[{}]+)|(?P<multilinecomment>/\*.*?\*/)|(?P<noncomment>\'(\\.|[^\\\'])*\'|"(\\.|[^\\"])*"|.[^/\'"]*)',
        re.DOTALL | re.MULTILINE)
    return ''.join([c.group('noncomment') for c in c_regex.finditer(string) if c.group('noncomment')])


def normalize(string):
    # Code for normalizing the input string.
    # LF and TAB literals, curly braces, and spaces are removed,
    # and all characters are lowercased.
    # ref: https://github.com/squizz617/vuddy
    return ''.join(string.replace('\n', '').replace('\r', '').replace('\t', '').replace('{', '').replace('}', '').split(
        ' ')).lower()

def decode_output(output):
    try:
        return output.decode('utf-8')
    except UnicodeDecodeError:
        return output.decode('latin-1', 'ignore')

def hashing(repoPath, saveCodePath):
    # This function is for hashing C/C++ functions
    # Only consider ".c", ".cc", and ".cpp" files
    possible = (".c", ".cc", ".cpp", "hpp", "hxx", "h")

    fileCnt = 0
    funcCnt = 0
    lineCnt = 0

    resDict = {}

    for path, dir, files in os.walk(repoPath):
        for file in files:
            filePath = os.path.join(path, file)

            if file.endswith(possible):
                try:
                    # Execute Ctags command
                    functionList = subprocess.check_output(
                        ctagsPath + ' -f - --kinds-C=* --fields=neKSt "' + filePath + '"', stderr=subprocess.STDOUT,
                        shell=True).decode()

                    f = open(filePath, 'r', encoding="UTF-8", errors='ignore')

                    # For parsing functions
                    lines = f.readlines()
                    allFuncs = str(functionList).split('\n')
                    func = re.compile(r'(function)')
                    number = re.compile(r'(\d+)')
                    funcSearch = re.compile(r'{([\S\s]*)}')
                    tmpString = ""
                    funcBody = ""

                    fileCnt += 1

                    for i in allFuncs:
                        elemList = re.sub(r'[\t\s ]{2,}', '', i)
                        elemList = elemList.split('\t')
                        funcBody = ""

                        if i != '' and len(elemList) >= 8 and func.fullmatch(elemList[3]):
                            funcName = elemList[0]  # Extract function name
                            funcStartLine = int(number.search(elemList[4]).group(0))
                            funcEndLine = int(number.search(elemList[7]).group(0))

                            tmpString = ""
                            tmpString = tmpString.join(lines[funcStartLine - 1: funcEndLine])

                            if funcSearch.search(tmpString):
                                funcBody = funcBody + funcSearch.search(tmpString).group(1)
                            else:
                                funcBody = " "

                            funcBody = removeComment(funcBody)
                            normalizedFuncBody = normalize(funcBody)
                            funcHash = computeTlsh(normalizedFuncBody)

                            if len(funcHash) == 72 and funcHash.startswith("T1"):
                                funcHash = funcHash[2:]
                            elif funcHash == "TNULL" or funcHash == "" or funcHash == "NULL":
                                continue

                            storedPath = filePath.replace(repoPath, "")
                            if funcHash not in resDict:
                                resDict[funcHash] = []

                            resDict[funcHash].append((storedPath, funcName))  # Save file path and function name

                            # Save original function body before hashing
                            if not os.path.exists(saveCodePath):
                                os.makedirs(saveCodePath)
                            with open(os.path.join(saveCodePath, f'{funcHash}.c'), 'w', encoding='utf-8') as funcFile:
                                funcFile.write(funcBody)

                            lineCnt += len(lines)
                            funcCnt += 1

                except subprocess.CalledProcessError as e:
                    print("Parser Error:", e)
                    continue
                except Exception as e:
                    print("Subprocess failed", e)
                    continue

    return resDict, fileCnt, funcCnt, lineCnt


def indexing(resDict, title, filePath):
    # For indexing each OSS
    with open(filePath, 'w') as fres:
        fres.write(title + '\n')

        for hashval in resDict:
            if hashval == '' or hashval == ' ':
                continue

            fres.write(hashval)

            for funcPath, funcName in resDict[hashval]:
                fres.write(f', {funcName}, {funcPath}')
            fres.write('\n')

def process_repo(eachUrl):
    os.chdir(currentPath)
    repoName = eachUrl.split("github.com/")[1].replace(".git", "").replace("/", "@@")  # Replace '/' -> '@@' for convenience
    print("[+] Processing", repoName)

    try:
        repo_dir = os.path.join(clonePath, repoName)
        # Clone the repository
        repo = git.Repo.clone_from(eachUrl, repo_dir)

        # Get tag dates
        tags = repo.tags
        with open(os.path.join(tagDatePath, repoName), 'w') as tag_date_file:
            for tag in tags:
                tag_date = repo.git.log(tag, n=1, format="%ai")
                tag_date_file.write(f"{tag_date} {tag}\n")

        branches = [branch.name for branch in repo.remote().refs]

        resDict = {}
        fileCnt = 0
        funcCnt = 0
        lineCnt = 0

        # Define the regex for filtering tags
        tagPattern = re.compile(r'^(v?\d+\.\d+\.\d+|v?\d+_\d+_\d+|\d+\.\d+\.\d+|\d+_\d+_\d+)$')
        valid_tags = [tag.name for tag in tags if tagPattern.match(tag.name)]

        # Check if master or main branch exists and add it to tags list
        if 'origin/master' in branches:
            valid_tags.append('master')
        if 'origin/main' in branches:
            valid_tags.append('main')

        if not valid_tags:
            # No valid tags or branches, use the default cloned state
            print(f"No valid tags or branches found for {repoName}, using default cloned state")
            resDict, fileCnt, funcCnt, lineCnt = hashing(repo_dir, os.path.join(funcCodePath, repoName, 'default'))
            if len(resDict) > 0:
                if not os.path.isdir(resultPath + repoName):
                    os.mkdir(resultPath + repoName)
                title = '\t'.join([repoName, str(fileCnt), str(funcCnt), str(lineCnt)])
                resultFilePath = resultPath + repoName + '/fuzzy_default.hidx'
                indexing(resDict, title, resultFilePath)
        else:
            for tag in valid_tags:
                try:
                    # Checkout the tag
                    if tag in ['master', 'main']:
                        repo.git.checkout(tag)
                    else:
                        repo.git.checkout(f'tags/{tag}', force=True)
                    resDict, fileCnt, funcCnt, lineCnt = hashing(repo_dir, os.path.join(funcCodePath, repoName, f'fuzzy_{tag}'))

                    if len(resDict) > 0:
                        if not os.path.isdir(resultPath + repoName):
                            os.mkdir(resultPath + repoName)
                        title = '\t'.join([repoName, str(fileCnt), str(funcCnt), str(lineCnt)])
                        resultFilePath = resultPath + repoName + f'/fuzzy_{tag}.hidx'
                        indexing(resDict, title, resultFilePath)
                except Exception as e:
                    print(f"Error checking out tag {tag} for {repoName}: {e}")

        # Remove the cloned repository from repo_src
        shutil.rmtree(repo_dir)

    except git.exc.GitCommandError as e:
        print("Parser Error:", e)
    except Exception as e:
        print("Subprocess failed", e)

def main():
    with open(gitCloneURLS, 'r', encoding="UTF-8", errors='ignore') as fp:
        funcDateDict = {}
        lines = [l.strip('\n\r') for l in fp.readlines()]

    # Use ThreadPoolExecutor to process repositories in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(process_repo, eachUrl) for eachUrl in lines]
        for future in concurrent.futures.as_completed(futures):
            try:
                future.result()
            except Exception as e:
                print(f"An error occurred: {e}")


""" EXECUTE """
if __name__ == "__main__":
    main()