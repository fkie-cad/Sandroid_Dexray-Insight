# -*- coding: utf_8 -*-
# flake8: noqa
"""Module for android manifest analysis."""
import logging

import requests
from concurrent.futures import ThreadPoolExecutor

#from mobsf.MobSF.utils import (
#    append_scan_status,
#    is_number,
#    upstream_proxy,
#    valid_host,
#)
#from mobsf.StaticAnalyzer.views.android import (
#    network_security,
#)
#from mobsf.StaticAnalyzer.views.android.kb import (
#    android_manifest_desc,
#)

from .android_manifest_desc import  MANIFEST_DESC
from .network_security import network_security_analysis
from .utils import is_number, valid_host


logger = logging.getLogger(__name__)
logging.getLogger("androguard").disabled = True
ANDROID_4_2_LEVEL = 17
ANDROID_5_0_LEVEL = 21
ANDROID_8_0_LEVEL = 26
ANDROID_9_0_LEVEL = 28
ANDROID_10_0_LEVEL = 29
ANDROID_MANIFEST_FILE = 'AndroidManifest.xml'
ANDROID_API_LEVEL_MAP = {
    '1': '1.0',
    '2': '1.1',
    '3': '1.5',
    '4': '1.6',
    '5': '2.0-2.1',
    '8': '2.2-2.2.3',
    '9': '2.3-2.3.2',
    '10': '2.3.3-2.3.7',
    '11': '3.0',
    '12': '3.1',
    '13': '3.2-3.2.6',
    '14': '4.0-4.0.2',
    '15': '4.0.3-4.0.4',
    '16': '4.1-4.1.2',
    '17': '4.2-4.2.2',
    '18': '4.3-4.3.1',
    '19': '4.4-4.4.4',
    '20': '4.4W-4.4W.2',
    '21': '5.0-5.0.2',
    '22': '5.1-5.1.1',
    '23': '6.0-6.0.1',
    '24': '7.0',
    '25': '7.1-7.1.2',
    '26': '8.0',
    '27': '8.1',
    '28': '9',
    '29': '10',
    '30': '11',
    '31': '12',
    '32': '12L',
    '33': '13',
    '34': '14',
}


def assetlinks_check(act_name, well_knowns):
    """Well known assetlink check."""
    findings = []

    with ThreadPoolExecutor() as executor:
        futures = []
        for w_url, host in well_knowns.items():
            logger.info(
                'App Link Assetlinks Check - [%s] %s', act_name, host)
            futures.append(
                executor.submit(_check_url, host, w_url))
        for future in futures:
            findings.append(future.result())

    return findings


def _check_url(host, w_url):
    try:
        iden = 'sha256_cert_fingerprints'
        #proxies, verify = upstream_proxy('https')
        status = False
        status_code = 0

        #r = requests.get(w_url,
        #                 timeout=5,
        #                 allow_redirects=False,
        #                 proxies=proxies,
        #                 verify=verify)

        r = requests.get(w_url,
                         timeout=5,
                         allow_redirects=False)

        status_code = r.status_code
        if status_code == 302:
            logger.warning('302 Redirect detected, skipping check')
            status = False
        if (str(status_code).startswith('2') and iden in str(r.json())):
            status = True

        return {'url': w_url,
                'host': host,
                'status_code': status_code,
                'status': status}

    except Exception:
        logger.error(f'Well Known Assetlinks Check for URL: {w_url}')
        return {'url': w_url,
                'host': host,
                'status_code': None,
                'status': False}


def get_browsable_activities(node, ns):
    """Get Browsable Activities."""
    try:
        browse_dic = {}
        schemes = []
        mime_types = []
        hosts = []
        ports = []
        paths = []
        path_prefixs = []
        path_patterns = []
        well_known = {}
        well_known_path = '/.well-known/assetlinks.json'
        catg = node.getElementsByTagName('category')
        for cat in catg:
            if cat.getAttribute(f'{ns}:name') == 'android.intent.category.BROWSABLE':
                data_tag = node.getElementsByTagName('data')
                for data in data_tag:
                    scheme = data.getAttribute(f'{ns}:scheme')
                    if scheme and scheme not in schemes:
                        schemes.append(scheme)
                    mime = data.getAttribute(f'{ns}:mimeType')
                    if mime and mime not in mime_types:
                        mime_types.append(mime)
                    host = data.getAttribute(f'{ns}:host')
                    if host and host not in hosts:
                        hosts.append(host)
                    port = data.getAttribute(f'{ns}:port')
                    if port and port not in ports:
                        ports.append(port)
                    path = data.getAttribute(f'{ns}:path')
                    if path and path not in paths:
                        paths.append(path)
                    path_prefix = data.getAttribute(f'{ns}:pathPrefix')
                    if path_prefix and path_prefix not in path_prefixs:
                        path_prefixs.append(path_prefix)
                    path_pattern = data.getAttribute(f'{ns}:pathPattern')
                    if path_pattern and path_pattern not in path_patterns:
                        path_patterns.append(path_pattern)
                    # Collect possible well-known paths
                    if (scheme
                        and scheme in ('http', 'https')
                        and host
                            and host != '*'):
                        host = host.replace('*.', '').replace('#', '')
                        if not valid_host(host):
                            continue
                        shost = f'{scheme}://{host}'
                        if port and is_number(port):
                            c_url = f'{shost}:{port}{well_known_path}'
                        else:
                            c_url = f'{shost}{well_known_path}'
                        well_known[c_url] = shost
        schemes = [scheme + '://' for scheme in schemes]
        browse_dic['schemes'] = schemes
        browse_dic['mime_types'] = mime_types
        browse_dic['hosts'] = hosts
        browse_dic['ports'] = ports
        browse_dic['paths'] = paths
        browse_dic['path_prefixs'] = path_prefixs
        browse_dic['path_patterns'] = path_patterns
        browse_dic['browsable'] = bool(browse_dic['schemes'])
        browse_dic['well_known'] = well_known
        return browse_dic
    except Exception:
        logger.exception('Getting Browsable Activities')


def _analyze_custom_permissions(mfxml, ns):
    """
    Analyze custom permission definitions and protection levels.
    
    Single Responsibility: Handle custom permission analysis only.
    """
    permission_dict = {}
    permissions = mfxml.getElementsByTagName('permission')
    
    for permission in permissions:
        if permission.getAttribute(f'{ns}:protectionLevel'):
            protectionlevel = permission.getAttribute(f'{ns}:protectionLevel')
            if protectionlevel == '0x00000000':
                protectionlevel = 'normal'
            elif protectionlevel == '0x00000001':
                protectionlevel = 'dangerous'
            elif protectionlevel == '0x00000002':
                protectionlevel = 'signature'
            elif protectionlevel == '0x00000003':
                protectionlevel = 'signatureOrSystem'

            permission_dict[permission.getAttribute(f'{ns}:name')] = protectionlevel
        elif permission.getAttribute(f'{ns}:name'):
            permission_dict[permission.getAttribute(f'{ns}:name')] = 'normal'
    
    return permission_dict


def _validate_sdk_versions(man_data_dic):
    """
    Validate SDK versions and identify security vulnerabilities.
    
    Single Responsibility: Handle SDK version security validation only.
    """
    findings = []
    
    if man_data_dic['min_sdk'] and int(man_data_dic['min_sdk']) < ANDROID_8_0_LEVEL:
        minsdk = man_data_dic.get('min_sdk')
        android_version = ANDROID_API_LEVEL_MAP.get(minsdk, 'XX')
        findings.append(('vulnerable_os_version', (android_version, minsdk,), ()))
    elif man_data_dic['min_sdk'] and int(man_data_dic['min_sdk']) < ANDROID_10_0_LEVEL:
        minsdk = man_data_dic.get('min_sdk')
        android_version = ANDROID_API_LEVEL_MAP.get(minsdk, 'XX')
        findings.append(('vulnerable_os_version2', (android_version, minsdk,), ()))
    
    return findings


def _analyze_application_configuration(mfxml, ns):
    """
    Analyze application-level security configurations.
    
    Single Responsibility: Handle application-level attribute analysis only.
    """
    findings = []
    applications = mfxml.getElementsByTagName('application')
    
    # Handle multiple application tags in AAR
    for application in applications:
        if application.getAttribute(f'{ns}:usesCleartextTraffic') == 'true':
            findings.append(('clear_text_traffic', (), ()))
        if application.getAttribute(f'{ns}:directBootAware') == 'true':
            findings.append(('direct_boot_aware', (), ()))
        if application.getAttribute(f'{ns}:networkSecurityConfig'):
            item = application.getAttribute(f'{ns}:networkSecurityConfig')
            findings.append(('has_network_security', (item,), ()))
        if application.getAttribute(f'{ns}:debuggable') == 'true':
            findings.append(('app_is_debuggable', (), ()))
        if application.getAttribute(f'{ns}:allowBackup') == 'true':
            findings.append(('app_allowbackup', (), ()))
        elif application.getAttribute(f'{ns}:allowBackup') == 'false':
            # Backup explicitly disabled - this is secure
            pass
        else:
            # allowBackup not set - default is true, which is insecure
            findings.append(('allowbackup_not_set', (), ()))
        if application.getAttribute(f'{ns}:testOnly') == 'true':
            findings.append(('app_in_test_mode', (), ()))
    
    return findings


def _determine_export_status(node, ns, itemname, permission_dict, perm_appl_level_exists=False):
    """
    Determine if a component is exported and the security implications.
    
    Single Responsibility: Handle component export status determination only.
    """
    is_exported = False
    export_reason = None
    protection_info = {}
    
    # Check explicit export attribute
    if node.getAttribute(f'{ns}:exported') == 'true':
        is_exported = True
        export_reason = 'explicitly_exported'
    elif node.getAttribute(f'{ns}:exported') == 'false':
        is_exported = False
        export_reason = 'explicitly_not_exported'
    else:
        # Check for implicit export via intent filters
        intent_filters = []
        for child in node.childNodes:
            if hasattr(child, 'nodeName') and child.nodeName == 'intent-filter':
                intent_filters.append(child)
        
        if intent_filters:
            is_exported = True
            export_reason = 'intent_filter_implicit'
    
    # Analyze permission protection if exported
    if is_exported:
        component_permission = node.getAttribute(f'{ns}:permission')
        if component_permission:
            protection_info = _analyze_permission_protection(component_permission, permission_dict)
        elif perm_appl_level_exists:
            protection_info = {'has_app_level_permission': True}
        else:
            protection_info = {'unprotected': True}
    
    return {
        'is_exported': is_exported,
        'export_reason': export_reason,
        'protection_info': protection_info
    }


def _analyze_permission_protection(permission_name, permission_dict):
    """
    Analyze the protection level and security implications of a permission.
    
    Single Responsibility: Handle permission protection analysis only.
    """
    if permission_name in permission_dict:
        protection_level = permission_dict[permission_name]
        
        security_assessment = {
            'protection_level': protection_level,
            'permission_defined': True
        }
        
        if protection_level in ['signature', 'signatureOrSystem']:
            security_assessment['is_secure'] = True
            security_assessment['risk_level'] = 'low'
        elif protection_level == 'dangerous':
            security_assessment['is_secure'] = False
            security_assessment['risk_level'] = 'high'
        elif protection_level == 'normal':
            security_assessment['is_secure'] = False
            security_assessment['risk_level'] = 'medium'
        
        return security_assessment
    else:
        return {
            'protection_level': 'unknown',
            'permission_defined': False,
            'is_secure': False,
            'risk_level': 'high'
        }


def _analyze_components(mfxml, ns, man_data_dic, permission_dict):
    """
    Analyze Android components (activities, services, receivers, providers).
    
    Single Responsibility: Handle component analysis and export determination only.
    """
    findings = []
    exported_activities = []
    exported_services = []
    exported_receivers = []
    exported_providers = []
    exp_count = dict.fromkeys(['act', 'ser', 'bro', 'cnt'], 0)
    
    applications = mfxml.getElementsByTagName('application')
    
    for application in applications:
        # Check for application-level permission
        perm_appl_level_exists = bool(application.getAttribute(f'{ns}:permission'))
        
        for node in application.childNodes:
            if not hasattr(node, 'nodeName'):
                continue
                
            # Map component types
            component_mapping = {
                'activity': ('Activity', 'act', 'n'),
                'activity-alias': ('Activity-Alias', 'act', 'n'),
                'provider': ('Content Provider', 'cnt', ''),
                'receiver': ('Broadcast Receiver', 'bro', ''),
                'service': ('Service', 'ser', '')
            }
            
            if node.nodeName not in component_mapping:
                continue
                
            itemname, cnt_id, an_or_a = component_mapping[node.nodeName]
            component_name = node.getAttribute(f'{ns}:name')
            
            if not component_name:
                continue
            
            # Analyze export status
            export_info = _determine_export_status(node, ns, itemname, permission_dict, perm_appl_level_exists)
            
            if export_info['is_exported'] and component_name != man_data_dic.get('mainactivity'):
                # Process exported component
                finding_data = _process_exported_component(
                    node, ns, itemname, component_name, export_info, an_or_a
                )
                
                if finding_data:
                    findings.append(finding_data)
                
                # Add to appropriate exported list
                if itemname in ['Activity', 'Activity-Alias']:
                    exported_activities.append(component_name)
                elif itemname == 'Service':
                    exported_services.append(component_name)
                elif itemname == 'Broadcast Receiver':
                    exported_receivers.append(component_name)
                elif itemname == 'Content Provider':
                    exported_providers.append(component_name)
                
                # Increment counter for certain protection levels
                if _should_count_as_exported(export_info):
                    exp_count[cnt_id] += 1
    
    return {
        'exported_activities': exported_activities,
        'exported_services': exported_services,
        'exported_receivers': exported_receivers,
        'exported_providers': exported_providers,
        'export_counts': exp_count,
        'findings': findings
    }


def _process_exported_component(node, ns, itemname, component_name, export_info, an_or_a):
    """
    Process an exported component and generate appropriate security findings.
    
    Single Responsibility: Generate security findings for exported components only.
    """
    protection_info = export_info.get('protection_info', {})
    
    if 'protection_level' in protection_info:
        # Component has permission protection
        prot_level = protection_info['protection_level']
        permission_name = node.getAttribute(f'{ns}:permission')
        perm_text = f'<strong>Permission: </strong>{permission_name}'
        
        if protection_info.get('permission_defined'):
            prot_text = f'</br><strong>protectionLevel: </strong>{prot_level}'
            
            if prot_level == 'normal':
                return ('exported_protected_permission_normal', 
                       (itemname, component_name, perm_text + prot_text), 
                       (an_or_a, itemname))
            elif prot_level == 'dangerous':
                return ('exported_protected_permission_dangerous',
                       (itemname, component_name, perm_text + prot_text),
                       (an_or_a, itemname))
            elif prot_level == 'signature':
                return ('exported_protected_permission_signature',
                       (itemname, component_name, perm_text + prot_text),
                       (an_or_a, itemname))
            elif prot_level == 'signatureOrSystem':
                return ('exported_protected_permission_signatureorsystem',
                       (itemname, component_name, perm_text + prot_text),
                       (an_or_a, itemname))
        else:
            return ('exported_protected_permission_not_defined',
                   (itemname, component_name, perm_text),
                   (an_or_a, itemname))
    elif protection_info.get('unprotected'):
        # Component is exported without permission protection
        return ('explicitly_exported', (itemname, component_name), (an_or_a, itemname))
    
    return None


def _should_count_as_exported(export_info):
    """
    Determine if a component should be counted as exported for statistics.
    
    Single Responsibility: Determine export counting logic only.
    """
    if not export_info.get('is_exported'):
        return False
    
    protection_info = export_info.get('protection_info', {})
    
    # Count as exported if unprotected or has weak protection
    if protection_info.get('unprotected'):
        return True
    
    if 'protection_level' in protection_info:
        prot_level = protection_info['protection_level']
        return prot_level in ['normal', 'dangerous', 'unknown']
    
    return False


def _analyze_grant_uri_permissions(mfxml, ns):
    """
    Analyze grant-uri-permission configurations for security issues.
    
    Single Responsibility: Handle URI permission analysis only.
    """
    findings = []
    granturipermissions = mfxml.getElementsByTagName('grant-uri-permission')
    
    for granturi in granturipermissions:
        if granturi.getAttribute(f'{ns}:pathPrefix') == '/':
            findings.append(('improper_provider_permission', ('pathPrefix=/',), ()))
        elif granturi.getAttribute(f'{ns}:path') == '/':
            findings.append(('improper_provider_permission', ('path=/',), ()))
        elif granturi.getAttribute(f'{ns}:pathPattern') == '*':
            findings.append(('improper_provider_permission', ('path=*',), ()))
    
    return findings


def _analyze_data_tags(mfxml, ns):
    """
    Analyze intent data tags for security issues.
    
    Single Responsibility: Handle data tag analysis only.
    """
    findings = []
    data_tags = mfxml.getElementsByTagName('data')
    
    for data in data_tags:
        if data.getAttribute(f'{ns}:scheme') == 'android_secret_code':
            xmlhost = data.getAttribute(f'{ns}:host')
            findings.append(('dialer_code_found', (xmlhost,), ()))
        elif data.getAttribute(f'{ns}:port'):
            dataport = data.getAttribute(f'{ns}:port')
            findings.append(('sms_receiver_port_found', (dataport,), ()))
    
    return findings


def _analyze_intent_priorities(mfxml, ns):
    """
    Analyze intent filter and action priorities for suspicious values.
    
    Single Responsibility: Handle intent priority analysis only.
    """
    findings = []
    intents = mfxml.getElementsByTagName('intent-filter')
    actions = mfxml.getElementsByTagName('action')
    
    # Check intent filter priorities
    for intent in intents:
        if intent.getAttribute(f'{ns}:priority').isdigit():
            value = intent.getAttribute(f'{ns}:priority')
            if int(value) > 100:
                findings.append(('high_intent_priority_found', (value,), ()))
    
    # Check action priorities
    for action in actions:
        if action.getAttribute(f'{ns}:priority').isdigit():
            value = action.getAttribute(f'{ns}:priority')
            if int(value) > 100:
                findings.append(('high_action_priority_found', (value,), ()))
    
    return findings


def _process_analysis_results(findings_list):
    """
    Convert raw analysis findings to structured output format.
    
    Single Responsibility: Handle result formatting and template processing only.
    """
    formatted_results = []
    
    for finding_key, title_params, desc_params in findings_list:
        template = MANIFEST_DESC.get(finding_key)
        if template:
            formatted_results.append({
                'rule': finding_key,
                'title': template['title'] % title_params,
                'severity': template['level'],
                'description': template['description'] % desc_params,
                'name': template['name'] % title_params,
                'component': title_params,
            })
        else:
            logger.warning("No template found for key '%s'", finding_key)
    
    return formatted_results


def _integrate_network_security(checksum, man_data_dic, do_netsec, src_type, app_dir):
    """
    Integrate network security configuration analysis.
    
    Single Responsibility: Handle network security integration only.
    """
    additional_findings = []
    
    # Check if app has launcher category (affects some security analysis)
    has_launcher = False
    for category in man_data_dic.get('categories', []):
        if category == 'android.intent.category.LAUNCHER':
            has_launcher = True
            break
    
    # Integrate network security analysis if configured
    if do_netsec and src_type == 'apk':
        try:
            network_findings = network_security_analysis(checksum, do_netsec, app_dir)
            if network_findings:
                additional_findings.extend(network_findings)
        except Exception as e:
            logger.warning("Failed to perform network security analysis: %s", e)
    
    return additional_findings


def manifest_analysis(checksum, mfxml, ns, man_data_dic, src_type, app_dir):
    """
    Analyze manifest file using specialized analysis functions.
    
    Refactored coordinator function that orchestrates all manifest analysis tasks
    following the Single Responsibility Principle. Each analysis concern is handled
    by a dedicated function.
    
    Args:
        checksum: Application checksum
        mfxml: Parsed manifest XML document
        ns: XML namespace (typically 'android')
        man_data_dic: Manifest metadata dictionary
        src_type: Source type ('apk', etc.)
        app_dir: Application directory path
        
    Returns:
        Dictionary containing comprehensive manifest analysis results
    """
    try:
        msg = 'Manifest Analysis Started'
        logger.info(msg)
        
        # Phase 1: Analyze custom permissions
        permission_dict = _analyze_custom_permissions(mfxml, ns)
        
        # Phase 2: Validate SDK versions for vulnerabilities  
        sdk_findings = _validate_sdk_versions(man_data_dic)
        
        # Phase 3: Analyze application-level security configuration
        app_config_findings = _analyze_application_configuration(mfxml, ns)
        
        # Phase 4: Analyze all Android components
        component_results = _analyze_components(mfxml, ns, man_data_dic, permission_dict)
        
        # Phase 5: Analyze grant-uri-permission configurations
        uri_permission_findings = _analyze_grant_uri_permissions(mfxml, ns)
        
        # Phase 6: Analyze intent data tags
        data_tag_findings = _analyze_data_tags(mfxml, ns)
        
        # Phase 7: Analyze intent priorities
        intent_priority_findings = _analyze_intent_priorities(mfxml, ns)
        
        # Phase 8: Combine all findings
        all_findings = (
            sdk_findings + 
            app_config_findings + 
            component_results['findings'] +
            uri_permission_findings +
            data_tag_findings +
            intent_priority_findings
        )
        
        # Phase 9: Process results into structured format
        processed_findings = _process_analysis_results(all_findings)
        
        # Phase 10: Integrate network security analysis
        network_security_findings = _integrate_network_security(checksum, man_data_dic, False, src_type, app_dir)
        
        # Phase 11: Collect browsable activities for later analysis
        browsable_activities = {}
        applications = mfxml.getElementsByTagName('application')
        for application in applications:
            for node in application.childNodes:
                if hasattr(node, 'nodeName') and node.nodeName in ['activity', 'activity-alias']:
                    browse_dic = get_browsable_activities(node, ns)
                    if browse_dic['browsable']:
                        browsable_activities[node.getAttribute(f'{ns}:name')] = browse_dic
        
        # Phase 12: Process permissions for output
        permissions = {}
        if 'perm' in man_data_dic:
            for k, permission in man_data_dic['perm'].items():
                permissions[k] = {
                    'status': permission[0],
                    'info': permission[1],
                    'description': permission[2],
                }
        
        # Phase 13: Count exported components
        exported_comp = {
            'exported_activities': len(component_results['exported_activities']),
            'exported_services': len(component_results['exported_services']),
            'exported_receivers': len(component_results['exported_receivers']),
            'exported_providers': len(component_results['exported_providers']),
        }
        
        # Phase 14: Determine network security analysis requirements
        do_netsec = False
        debuggable = False
        applications = mfxml.getElementsByTagName('application')
        for application in applications:
            if application.getAttribute(f'{ns}:networkSecurityConfig'):
                do_netsec = application.getAttribute(f'{ns}:networkSecurityConfig')
            if application.getAttribute(f'{ns}:debuggable') == 'true':
                debuggable = True
        
        # Phase 15: Build final result dictionary
        man_an_dic = {
            'manifest_anal': processed_findings + network_security_findings,
            'exported_act': component_results['exported_activities'],
            'exported_ser': component_results['exported_services'],
            'exported_rec': component_results['exported_receivers'],
            'exported_pro': component_results['exported_providers'],
            'exported_cnt': exported_comp,
            'browsable_activities': browsable_activities,
            'permissions': permissions,
            'network_security': network_security_analysis(
                checksum,
                app_dir,
                do_netsec,
                debuggable,
                src_type),
        }
        return man_an_dic
    except Exception as exp:
        msg = 'Error Performing Manifest Analysis'
        logger.exception(msg)