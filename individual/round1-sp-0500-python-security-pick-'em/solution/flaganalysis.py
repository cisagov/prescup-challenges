import sys


bad0 = 'unsafe reason: eval function'
bad1 = 'unsafe reason: open file and exec'
bad2 = 'unsafe reason: load pickled file'
bad3 = 'unsafe reason: load arbitrary xml file'
good0 = 'safe reason: self-contained shell command use'
good1 = 'safe reason: mitigates danger by using ast.literal_eval instead of eval'
good2 = 'safe reason: mitigates danger by sanitizing input'
good3 = 'safe reason: pickle loading from a hard-coded pickled string'
correct = {'Gw': bad0, 'Oo': bad1, 'tZ': bad2, 'xC': bad3, 'EZ': good0, 'Ja': good1, 'WG': good2, 'Xv': good3}
incorrect = {'eN': 'Gw', 'Io': 'Oo', 'fr': 'tZ', 'KG': 'xC', 'jk': 'EZ', 'Pl': 'Ja', 'We': 'WG', 'vu' : 'Xv'}


def main():
    if len(sys.argv) != 2:
        print('Enter a challenge flag and nothing else.')
        return

    flag = sys.argv[1]
    if len(flag) != 8:
        print('Flag length is not valid - it should be exactly 8 characters.')
        return

    chunks = (flag[0:2], flag[2:4], flag[4:6], flag[6:8])

    print(chunks)

    reasons = []

    number_correct = 0
    for chunk in chunks:
        if chunk in correct:
            number_correct += 1
            reasons.append('CORRECT: ' + chunk + ' | REASON: ' + correct[chunk])
        elif chunk in incorrect:
            correct_flag = incorrect[chunk]
            reasons.append('INCORRECT: ' + chunk + ' should be ' + incorrect[chunk] + ' | REASON: ' + correct[correct_flag])
        else:
            reasons.append('INVALID: ' + chunk + ' | REASON: given chunk is not valid in this challenge')

    print('%d out of 4 correct' % number_correct)
    print('\n'.join(reasons))


if __name__ == '__main__':
    main()
