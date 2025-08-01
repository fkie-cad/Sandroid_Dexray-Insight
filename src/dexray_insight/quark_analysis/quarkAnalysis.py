from quark.engine import QuarkEngine

def Quark_analysis(path):
    """
    Analyse the apk with the quark engine
    for information about quark refer to https://github.com/quark-engine/quark-engine

    arguments:
    path:  the absolute path to the target apk

    returns: dict  (subject to change)
    """

    quark = QuarkEngine()

    result = quark.analyze(apk_path = path, #path to target apk
                           rule_path = None, #uses default rules for now TODO specify, write and add custom rules
                           report_path = "./report.json", #target directory for json report (optional)
                           enable_hooks = False) #use to hook onto methods


    print(result) #testing only purpose

    return result #TODO format result or maybe use the report generated in the report path