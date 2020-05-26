/**
* @kind path-problem
*/

import cpp
import semmle.code.cpp.dataflow.TaintTracking
import DataFlow::PathGraph
 
class NetworkByteSwap extends Expr {
  NetworkByteSwap () {
    exists(MacroInvocation mi | mi.getExpr() = this
                                and mi.getMacroName().regexpMatch("^ntoh.*$"))
  }
}

 
class Config extends TaintTracking::Configuration {
  Config() { this = "NetworkToMemFuncLength" }

  override predicate isSource(DataFlow::Node source) {
    source.asExpr() instanceof NetworkByteSwap 
  }

  override predicate isSink(DataFlow::Node sink) {
    sink.asParameter().getFunction().getName() = "memcpy"
    and sink.asParameter().getIndex() = 2
  }
}


from Config cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, source, sink, "Network byte swap flows to memcpy"
