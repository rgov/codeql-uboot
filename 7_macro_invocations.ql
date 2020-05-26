import cpp

from MacroInvocation mi
where mi.getMacroName().regexpMatch("^ntoh.*$")
select mi, "a network ordering conversion macro invocation"
