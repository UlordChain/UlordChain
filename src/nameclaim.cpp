#include "nameclaim.h"
#include "hash.h"
#include "util.h"

/*****************************************************************************
 函 数 名: uint32_t_to_vch
 功能描述  : 无符号int转换成无符号的char
 输入参数  : uint32_t n  
 输出参数  : 无
 返 回 值  : std::vector<unsigned char>
 调用函数  : 
 被调函数  : 
 
 修改历史     :
  1.日    期  : 2017年10月30日
    作    者  : zhoukaiyuan
    修改内容   : 新生成函数

*****************************************************************************/
std::vector<unsigned char> uint32_t_to_vch(uint32_t n)
{
    std::vector<unsigned char> vchN;
    vchN.resize(4);
    vchN[0] = n >> 24;
    vchN[1] = n >> 16;
    vchN[2] = n >> 8;
    vchN[3] = n;
    return vchN;
}

/*****************************************************************************
 函 数 名: vch_to_uint32_t
 功能描述  : 无符号的char转换成无符号int
 输入参数  : uint32_t n  
 输出参数  : 无
 返 回 值  : std::vector<unsigned char>
 调用函数  : 
 被调函数  : 
 
 修改历史     :
  1.日    期  : 2017年10月30日
    作    者  : zhoukaiyuan
    修改内容   : 新生成函数

*****************************************************************************/
uint32_t vch_to_uint32_t(std::vector<unsigned char>& vchN)
{
    uint32_t n;
    if (vchN.size() != 4)
    {
        LogPrintf("%s() : a vector<unsigned char> with size other than 4 has been given", __func__);
        return 0;
    }
    n = vchN[0] << 24 | vchN[1] << 16 | vchN[2] << 8 | vchN[3];
    return n;
}

/*****************************************************************************
 函 数 名: ClaimNameScript
 功能描述  : 认领脚本的名称
 输入参数  : std::string name   
           std::string value  
 输出参数  : 无
 返 回 值: CScript
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期  : 2017年10月30日
    作    者  : zhoukaiyuan
    修改内容   : 新生成函数

*****************************************************************************/
CScript ClaimNameScript(std::string name, std::string value)
{
     std::vector<unsigned char> vchName(name.begin(), name.end());
     std::vector<unsigned char> vchValue(value.begin(), value.end());
     return CScript() << OP_CLAIM_NAME << vchName << vchValue << OP_2DROP << OP_DROP << OP_TRUE; 
}

/*****************************************************************************
 函 数 名: SupportClaimScript
 功能描述  : 认领脚本的支持
 输入参数  : std::string name  
           uint160 claimId   
 输出参数  : 无
 返 回 值: CScript
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期  : 2017年10月30日
    作    者  : zhoukaiyuan
    修改内容   : 新生成函数

*****************************************************************************/
CScript SupportClaimScript(std::string name, uint160 claimId)
{
    std::vector<unsigned char> vchName(name.begin(), name.end());
    std::vector<unsigned char> vchClaimId(claimId.begin(),claimId.end());  
    return CScript() << OP_SUPPORT_CLAIM << vchName << vchClaimId << OP_2DROP << OP_DROP << OP_TRUE;
}

/*****************************************************************************
 函 数 名: UpdateClaimScript
 功能描述  : 认领脚本的更新
 输入参数  : std::string name   
             uint160 claimId    
             std::string value  
 输出参数  : 无
 返 回 值  : CScript
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2017年10月30日
    作    者   : zhoukaiyuan
    修改内容   : 新生成函数

*****************************************************************************/
CScript UpdateClaimScript(std::string name, uint160 claimId, std::string value)
{
    std::vector<unsigned char> vchName(name.begin(), name.end());
    std::vector<unsigned char> vchClaimId(claimId.begin(),claimId.end());  
    std::vector<unsigned char> vchValue(value.begin(), value.end());
    return CScript() << OP_UPDATE_CLAIM << vchName << vchClaimId << vchValue << OP_2DROP << OP_2DROP << OP_TRUE;
}

/*****************************************************************************
 函 数 名: DecodeClaimScript
 功能描述  : 对有要求的脚本解码
 输入参数  : const CScript& scriptIn                               
             int& op                                               
             std::vector<std::vector<unsigned char> >& vvchParams  
 输出参数  : 无
 返 回 值  : bool
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2017年10月30日
    作    者   : zhoukaiyuan
    修改内容   : 新生成函数

*****************************************************************************/
bool DecodeClaimScript(const CScript& scriptIn, int& op, std::vector<std::vector<unsigned char> >& vvchParams)
{
    CScript::const_iterator pc = scriptIn.begin();
    return DecodeClaimScript(scriptIn, op, vvchParams, pc);
}

/*****************************************************************************
 函 数 名: DecodeClaimScript
 功能描述  : 取出脚本的操作数指令
 输入参数  : const CScript& scriptIn                               
             int& op                                               
             std::vector<std::vector<unsigned char> >& vvchParams  
             CScript::const_iterator& pc                           
 输出参数  : 无
 返 回 值  : bool
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2017年10月30日
    作    者   : zhoukaiyuan
    修改内容   : 新生成函数

*****************************************************************************/
bool DecodeClaimScript(const CScript& scriptIn, int& op, std::vector<std::vector<unsigned char> >& vvchParams, CScript::const_iterator& pc)
{
    opcodetype opcode;
    if (!scriptIn.GetOp(pc, opcode))
    {
        return false;
    }
    
    if (opcode != OP_CLAIM_NAME && opcode != OP_SUPPORT_CLAIM && opcode != OP_UPDATE_CLAIM)
    {
        return false;
    }

    op = opcode;

    std::vector<unsigned char> vchParam1;
    std::vector<unsigned char> vchParam2;
    std::vector<unsigned char> vchParam3;
    // Valid formats:
    // OP_CLAIM_NAME vchName vchValue OP_2DROP OP_DROP pubkeyscript
    // OP_UPDATE_CLAIM vchName vchClaimId vchValue OP_2DROP OP_2DROP pubkeyscript
    // OP_SUPPORT_CLAIM vchName vchClaimId OP_2DROP OP_DROP pubkeyscript
    // All others are invalid.

    if (!scriptIn.GetOp(pc, opcode, vchParam1) || opcode < 0 || opcode > OP_PUSHDATA4)
    {
        return false;
    }
    if (!scriptIn.GetOp(pc, opcode, vchParam2) || opcode < 0 || opcode > OP_PUSHDATA4)
    {
        return false;
    }
    if (op == OP_UPDATE_CLAIM || op == OP_SUPPORT_CLAIM)
    {
        if (vchParam2.size() != 160/8)
        {
            return false;
        }
    }
    if (op == OP_UPDATE_CLAIM)
    {
        if (!scriptIn.GetOp(pc, opcode, vchParam3) || opcode < 0 || opcode > OP_PUSHDATA4)
        {
            return false;
        }
    }
    if (!scriptIn.GetOp(pc, opcode) || opcode != OP_2DROP)
    {
        return false;
    }
    if (!scriptIn.GetOp(pc, opcode))
    {
        return false;
    }
    if ((op == OP_CLAIM_NAME || op == OP_SUPPORT_CLAIM) && opcode != OP_DROP)
    {
        return false;
    }
    else if ((op == OP_UPDATE_CLAIM) && opcode != OP_2DROP)
    {
        return false;
    }

    vvchParams.push_back(vchParam1);
    vvchParams.push_back(vchParam2);
    if (op == OP_UPDATE_CLAIM)
    {
        vvchParams.push_back(vchParam3);
    }
    return true;
}

/*****************************************************************************
 函 数 名  : ClaimIdHash
 功能描述  : 认领hashID
 输入参数  : const uint256& txhash  
             uint32_t nOut          
 输出参数  : 无
 返 回 值  : uint160
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2017年10月30日
    作    者   : zhoukaiyuan
    修改内容   : 新生成函数

*****************************************************************************/
uint160 ClaimIdHash(const uint256& txhash, uint32_t nOut)
{
    std::vector<unsigned char> claimToHash(txhash.begin(), txhash.end());
    std::vector<unsigned char> vchnOut = uint32_t_to_vch(nOut);
    claimToHash.insert(claimToHash.end(), vchnOut.begin(), vchnOut.end());
    return Hash160(claimToHash);
}

CScript StripClaimScriptPrefix(const CScript& scriptIn)
{
    int op;
    return StripClaimScriptPrefix(scriptIn, op);
}

CScript StripClaimScriptPrefix(const CScript& scriptIn, int& op)
{
    std::vector<std::vector<unsigned char> > vvchParams;
    CScript::const_iterator pc = scriptIn.begin();

    if (!DecodeClaimScript(scriptIn, op, vvchParams, pc))
    {
        return scriptIn;
    }

    return CScript(pc, scriptIn.end());
}

/*****************************************************************************
 函 数 名  : ClaimScriptSize
 功能描述  : 认领脚本的大小
 输入参数  : const CScript& scriptIn  
 输出参数  : 无
 返 回 值  : size_t
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2017年10月30日
    作    者   : zhoukaiyuan
    修改内容   : 新生成函数

*****************************************************************************/
size_t ClaimScriptSize(const CScript& scriptIn)
{
    CScript strippedScript = StripClaimScriptPrefix(scriptIn);
    return scriptIn.size() - strippedScript.size();
}

size_t ClaimNameSize(const CScript& scriptIn)
{
    std::vector<std::vector<unsigned char> > vvchParams;
    CScript::const_iterator pc = scriptIn.begin();
    int op;
    if (!DecodeClaimScript(scriptIn, op, vvchParams, pc))
    {
        return 0;
    }
    else
    {
        return vvchParams[0].size();
    }
}
