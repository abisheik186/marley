frappe.listview_settings["Treatment Plan Consent"] = {
	filters: [["status", "=", "Active"]],
	get_indicator: function(doc) {
		var colors = {
			"Active": "green",
			"Completed": "blue",
			"Closed": "grey"
		};
		return [__(doc.status), colors[doc.status], "status,=," + doc.status];
	}
};
