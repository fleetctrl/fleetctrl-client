export namespace database {
	
	export class AppEvent {
	    id: number;
	    release_id: string;
	    app_id: string;
	    event_type: string;
	    source: string;
	    message?: string;
	    details_json?: string;
	    // Go type: time
	    created_at: any;
	
	    static createFrom(source: any = {}) {
	        return new AppEvent(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.release_id = source["release_id"];
	        this.app_id = source["app_id"];
	        this.event_type = source["event_type"];
	        this.source = source["source"];
	        this.message = source["message"];
	        this.details_json = source["details_json"];
	        this.created_at = this.convertValues(source["created_at"], null);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class ManagedAppState {
	    release_id: string;
	    app_id: string;
	    display_name: string;
	    publisher?: string;
	    version?: string;
	    installer_type: string;
	    winget_id?: string;
	    assign_type: string;
	    desired_action: string;
	    detected_status: string;
	    operation_status: string;
	    // Go type: time
	    first_seen_installed_at?: any;
	    // Go type: time
	    installed_by_client_at?: any;
	    // Go type: time
	    last_checked_at?: any;
	    // Go type: time
	    last_seen_on_server_at: any;
	    // Go type: time
	    assignment_removed_at?: any;
	    last_error?: string;
	    // Go type: time
	    created_at: any;
	    // Go type: time
	    updated_at: any;
	
	    static createFrom(source: any = {}) {
	        return new ManagedAppState(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.release_id = source["release_id"];
	        this.app_id = source["app_id"];
	        this.display_name = source["display_name"];
	        this.publisher = source["publisher"];
	        this.version = source["version"];
	        this.installer_type = source["installer_type"];
	        this.winget_id = source["winget_id"];
	        this.assign_type = source["assign_type"];
	        this.desired_action = source["desired_action"];
	        this.detected_status = source["detected_status"];
	        this.operation_status = source["operation_status"];
	        this.first_seen_installed_at = this.convertValues(source["first_seen_installed_at"], null);
	        this.installed_by_client_at = this.convertValues(source["installed_by_client_at"], null);
	        this.last_checked_at = this.convertValues(source["last_checked_at"], null);
	        this.last_seen_on_server_at = this.convertValues(source["last_seen_on_server_at"], null);
	        this.assignment_removed_at = this.convertValues(source["assignment_removed_at"], null);
	        this.last_error = source["last_error"];
	        this.created_at = this.convertValues(source["created_at"], null);
	        this.updated_at = this.convertValues(source["updated_at"], null);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class SyncRun {
	    id: string;
	    kind: string;
	    trigger: string;
	    status: string;
	    // Go type: time
	    started_at?: any;
	    // Go type: time
	    completed_at?: any;
	    error_message?: string;
	    details_json?: string;
	    // Go type: time
	    created_at: any;
	
	    static createFrom(source: any = {}) {
	        return new SyncRun(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.kind = source["kind"];
	        this.trigger = source["trigger"];
	        this.status = source["status"];
	        this.started_at = this.convertValues(source["started_at"], null);
	        this.completed_at = this.convertValues(source["completed_at"], null);
	        this.error_message = source["error_message"];
	        this.details_json = source["details_json"];
	        this.created_at = this.convertValues(source["created_at"], null);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace protocol {
	
	export class Overview {
	    service_available: boolean;
	    service_version: string;
	    server_url: string;
	    current_run?: database.SyncRun;
	    last_attempt?: database.SyncRun;
	    last_success?: database.SyncRun;
	    last_error?: database.SyncRun;
	    // Go type: time
	    checked_at: any;
	
	    static createFrom(source: any = {}) {
	        return new Overview(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.service_available = source["service_available"];
	        this.service_version = source["service_version"];
	        this.server_url = source["server_url"];
	        this.current_run = this.convertValues(source["current_run"], database.SyncRun);
	        this.last_attempt = this.convertValues(source["last_attempt"], database.SyncRun);
	        this.last_success = this.convertValues(source["last_success"], database.SyncRun);
	        this.last_error = this.convertValues(source["last_error"], database.SyncRun);
	        this.checked_at = this.convertValues(source["checked_at"], null);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

