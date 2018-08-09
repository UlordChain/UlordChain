
#include "netbase.h"
#include "masternodeconfig.h"
#include "util.h"
#include "chainparams.h"

#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>

CMasternodeConfig masternodeConfig;

void CMasternodeConfig::add(std::string alias, std::string ip, std::string privKey, std::string txHash, std::string outputIndex) {
    CMasternodeEntry cme(alias, ip, privKey, txHash, outputIndex);
    entries.push_back(cme);
}

bool CMasternodeConfig::read(std::string& strErr) {

    std::string alias, ip, privKey, txHash, outputIndex;
    alias = GetArg("-alias", "mnl");
    if(alias.empty())
    {
        strErr = _("please add your masternode name into ulord.conf; for example: alias=mynode\n");
    }
    ip = GetArg("-externalip", "");
    if(ip.empty())
    {
        strErr = _("Invalid masternode ip, please add your ip into ulord.conf; for example: externalip=0.0.0.0\n");
        return false;
    }
    ip = ip + ":" + std::to_string(Params().GetDefaultPort());
    
    privKey = GetArg("-masternodeprivkey", "");
    if(privKey.empty())
    {
        strErr = _("Invalid masternode privKey, please add your privKey into ulord.conf; for example: masternodeprivkey=***\n");
        return false;
    }
    txHash = GetArg("-collateral_output_txid", "");
    if(txHash.empty())
    {
        strErr = _("Invalid masternode collateral txid, please add your collateral txid into ulord.conf; for example: collateral_output_txid=***\n");
        return false;
    }

    outputIndex = GetArg("-collateral_output_index", "");
    if(outputIndex.empty())
    {
        strErr = _("Invalid masternode collateral Index, please add your collateral Index into ulord.conf; for example: collateral_output_index=0\n");
        return false;
    }
    
    int port = 0;
    std::string hostname = "";
    SplitHostPort(ip, port, hostname);
    if(port == 0 || hostname == "") {
        strErr = _("Failed to parse host:port string") + "\n";
        return false;
    }
    int mainnetDefaultPort = Params(CBaseChainParams::MAIN).GetDefaultPort();
    if(Params().NetworkIDString() == CBaseChainParams::MAIN) {
        if(port != mainnetDefaultPort) {
            strErr = _("Invalid port detected in ulord.conf") + "\n" +
                    strprintf(_("Port: %d"), port) + "\n" +
                    strprintf(_("(must be %d for mainnet)"), mainnetDefaultPort);
            return false;
        }
    } else if(port == mainnetDefaultPort) {
        strErr = _("Invalid port detected in ulord.conf") + "\n" +
                strprintf(_("(%d could be used only on mainnet)"), mainnetDefaultPort);
        return false;
    }
        
    add(alias, ip, privKey, txHash, outputIndex);

    return true;
}

CMasternodeConfig::CMasternodeEntry CMasternodeConfig::GetLocalEntry()
{
	if(fMasterNode)
	{
		for(auto & mn : entries)
		{
			if(mn.getPrivKey() == GetArg("-masternodeprivkey", ""))
				return mn;
		}
	}
	return CMasternodeEntry();
}

bool CMasternodeConfig::IsLocalEntry()
{
	if(fMasterNode)
	{
		for(auto & mn : entries)
		{
			if(mn.getPrivKey() == GetArg("-masternodeprivkey", "") && GetArg("-masternodeprivkey", "") != "" 
				&& GetArg("-broadcastSign", "") != "")
				return true;
		}
	}
	return false;
}


