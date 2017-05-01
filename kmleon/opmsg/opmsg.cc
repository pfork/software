#include <string>
#include <memory>
#include <unistd.h>
#include <stdlib.h>
#include "opmsg/misc.h"
#include "opmsg/keystore.h"

using namespace std;
using namespace opmsg;

// hex lower case
static string hlc(const string &s)
{
	string r = s;

	for (string::size_type i = 0; i < r.size(); ++i) {
		if (r[i] >= 'A' && r[i] <= 'F')
			r[i] += ('a' - 'A');
	}
	return r;
}


// name or ID inside opmsg keystore?
string has_opmsg_id(const string &r)
{
	bool return_r = 0, is_hex = 0;
	string rcpt = r, id = "", cfg = "";

	if (r.find("0x") == 0)
		rcpt = hlc(r.substr(2));

	if (is_hex_hash(rcpt))
		is_hex = 1;
	else
		rcpt = r;

	// if multiple space-separated 0x key id's appear, split off first one
	if (r.find("0x") == 0 && r.find("0x", 1) != string::npos) {
		string::size_type idx = r.find(" ");
		if (idx == string::npos || idx < 3)
			return id;
		rcpt = r.substr(0, idx);
		is_hex = 1;
		return_r = 1;
	}


	if (getenv("HOME"))
		cfg = getenv("HOME");
	cfg += "/.opmsg";

	// hash algo not relevant for searching
	unique_ptr<keystore> ks(new (nothrow) keystore("sha256", cfg));
	if (!ks.get() || ks->load() < 0)
		return 0;

	// if hex id as rcpt, try right away
	if (is_hex) {
		if (rcpt.find("0x") == 0)
			rcpt.erase(0, 2);
		persona *p = ks->find_persona(rcpt);
		if (p)
			id = p->get_id();
	}

	// not found? Try the same as 'name'
	if (id.size() == 0) {
		// try to match via alias name (first match counts)
		for (auto i = ks->first_pers(); i != ks->end_pers(); i = ks->next_pers(i)) {
			if (i->second->get_name().find(rcpt) != string::npos) {
				id = i->second->get_id();
				break;
			}
		}
	}

	// If we found opmsg persona id but have had multiple id's,
	// return them
	if (id.size() > 0) {
		if (return_r)
			return r;
		return rcpt;
	}

	return "";
}
