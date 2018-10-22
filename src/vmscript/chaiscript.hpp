// This file is distributed under the BSD License.
// See "license.txt" for details.


#ifndef CHAISCRIPT_HPP_
#define CHAISCRIPT_HPP_

/// this is a script test
/// use chaiscript as ulord script


#include "chaiscript_basic.hpp"
#include "language/chaiscript_parser.hpp"
#include "chaiscript_stdlib.hpp"


namespace chaiscript 
{
  class ChaiScript : public ChaiScript_Basic
  {
    public:
      ChaiScript(std::vector<std::string> t_modulepaths = {},
          std::vector<std::string> t_usepaths = {},
          const std::vector<Options> &t_opts = chaiscript::default_options())
        : ChaiScript_Basic(
            chaiscript::Std_Lib::library(),
            std::make_unique<parser::ChaiScript_Parser<eval::Noop_Tracer, optimizer::Optimizer_Default>>(),
            t_modulepaths, t_usepaths, t_opts)
        {
        }
  };
}

#endif /* CHAISCRIPT_HPP_ */
