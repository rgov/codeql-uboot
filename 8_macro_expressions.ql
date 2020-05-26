import cpp

from MacroInvocation mi
where mi.getMacroName().regexpMatch("^ntoh.*$")
select mi.getExpr(), "a network ordering conversion macro invocation"
