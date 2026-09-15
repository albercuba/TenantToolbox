import { useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";

type UserResult = { tenant_id: string; tenant_name: string; user_id: string; display_name: string; user_principal_name: string; account_enabled: boolean; license_types: string[]; department: string; groups: string[]; mfa_settings: string };
export type UserActionKey = "reset_password" | "block" | "revoke_sessions" | "register_mfa" | "create_tap" | "out_of_office" | "global_address_list" | "email_forwarding" | "m365_groups" | "security_groups" | "shared_mailboxes" | "distribution_groups" | "licenses" | "offboard";

type Group = { id: string; display_name: string; description?: string; mail?: string | null; category?: string; is_member: boolean };
type License = { sku_id: string; sku_part_number?: string; display_name?: string; service_plans?: unknown[] };
type Mailbox = { id?: string; alias?: string; display_name?: string; primary_smtp_address?: string; recipient_type_details?: string };
type AutomaticReplies = { status?: string; internalReplyMessage?: string; externalReplyMessage?: string; scheduledStartDateTime?: string; scheduledEndDateTime?: string };

const actionTitles: Record<UserActionKey, string> = { reset_password: "Reset password", block: "Block sign-in", revoke_sessions: "Sign-Out of All Apps", register_mfa: "Re-Register MFA", create_tap: "Create TAP", out_of_office: "Out of Office", global_address_list: "Global Address List", email_forwarding: "Manage Email Forwarding", m365_groups: "Manage M365 groups", security_groups: "Manage Security groups", shared_mailboxes: "Manage Shared mailboxes", distribution_groups: "Manage Distribution groups", licenses: "Manage Licenses", offboard: "Offboard User" };
const steps: Record<UserActionKey, string[]> = { reset_password: ["Configure", "Options", "Finish"], block: ["Configure", "Finish"], revoke_sessions: ["Finish"], register_mfa: ["Configure", "Options", "Finish"], create_tap: ["Configure", "Finish"], out_of_office: ["Configure", "Options", "Finish"], global_address_list: ["Configure", "Finish"], email_forwarding: ["Configure", "Options", "Finish"], m365_groups: ["Configure", "Finish"], security_groups: ["Configure", "Finish"], shared_mailboxes: ["Configure", "Options", "Finish"], distribution_groups: ["Configure", "Finish"], licenses: ["Configure", "Options", "Finish"], offboard: ["Setup", "Mailbox handling", "Access & identity", "Groups & licenses", "Data", "Finish"] };
const implemented: UserActionKey[] = ["reset_password", "block", "revoke_sessions", "register_mfa", "create_tap", "out_of_office", "global_address_list", "email_forwarding", "m365_groups", "security_groups", "shared_mailboxes", "distribution_groups", "licenses", "offboard"];

function Icon({ children }: { children: ReactNode }) { return <svg className="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">{children}</svg>; }
function Toggle({ label, checked, onChange, disabled = false }: { label: string; checked: boolean; onChange: (value: boolean) => void; disabled?: boolean }) { return <label className={`action-toggle ${disabled ? "disabled" : ""}`}><span>{label}</span><input type="checkbox" checked={checked} disabled={disabled} onChange={(event) => onChange(event.target.checked)} /><i /></label>; }
function Choice({ label, checked, onChange }: { label: string; checked: boolean; onChange: () => void }) { return <label className="action-choice"><input type="radio" checked={checked} onChange={onChange} />{label}</label>; }
function Check({ label, checked, onChange, disabled = false }: { label: string; checked: boolean; onChange: (value: boolean) => void; disabled?: boolean }) { return <label className={`action-check ${disabled ? "disabled" : ""}`}><input type="checkbox" checked={checked} disabled={disabled} onChange={(event) => onChange(event.target.checked)} />{label}</label>; }
function Summary({ items }: { items: string[] }) { return <div className="action-summary">{items.map((item) => <div key={item}><Icon><path d="m5 12 4 4L19 6" /></Icon><span>{item}</span></div>)}</div>; }

async function request<T>(url: string, token: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, { ...init, headers: { Authorization: `Bearer ${token}`, ...(init?.headers || {}) } });
  if (response.status === 401) { localStorage.removeItem("tenanttoolbox_token"); window.location.reload(); throw new Error("Your session expired. Please sign in again."); }
  const text = await response.text();
  let body: unknown;
  try { body = text ? JSON.parse(text) : undefined; } catch { body = undefined; }
  if (!response.ok) throw new Error(body && typeof body === "object" && "detail" in body ? String(body.detail) : text || "Request failed");
  return body as T;
}

export function UserActionDrawer({ user, actionKey, token, onClose, onMessage }: { user: UserResult; actionKey: UserActionKey; token: string; onClose: () => void; onMessage: (message: string) => void }) {
  const title = actionTitles[actionKey];
  const actionSteps = steps[actionKey];
  const [step, setStep] = useState(0); const [busy, setBusy] = useState(false); const [dataLoading, setDataLoading] = useState(false); const [dataError, setDataError] = useState("");
  const [passwordMode, setPasswordMode] = useState("auto"); const [password, setPassword] = useState(""); const [forceChange, setForceChange] = useState(true); const [revoke, setRevoke] = useState(true); const [blockSignIn, setBlockSignIn] = useState(true); const [reason, setReason] = useState(""); const [registeredMethods, setRegisteredMethods] = useState(["Authenticator app", "Phone", "FIDO2 key", "Windows Hello"]); const [tapLifetime, setTapLifetime] = useState("60");
  const [replyStatus, setReplyStatus] = useState("disabled"); const [replyStart, setReplyStart] = useState(""); const [replyEnd, setReplyEnd] = useState(""); const [internalReply, setInternalReply] = useState(""); const [externalReply, setExternalReply] = useState("");
  const [hideGal, setHideGal] = useState(true); const [forwarding, setForwarding] = useState(false); const [recipient, setRecipient] = useState(""); const [keepCopy, setKeepCopy] = useState(true);
  const [groups, setGroups] = useState<Group[]>([]); const [groupSearch, setGroupSearch] = useState(""); const [licenses, setLicenses] = useState<License[]>([]); const [availableLicenses, setAvailableLicenses] = useState<License[]>([]); const [mailboxes, setMailboxes] = useState<Mailbox[]>([]); const [selectedMailbox, setSelectedMailbox] = useState(""); const [fullAccess, setFullAccess] = useState(true); const [sendAs, setSendAs] = useState(false); const [sendOnBehalf, setSendOnBehalf] = useState(false); const [autoMapping, setAutoMapping] = useState(true);
  const [convertMailbox, setConvertMailbox] = useState(true); const [disableAccount, setDisableAccount] = useState(true); const [offboardSessions, setOffboardSessions] = useState(true); const [removeGroups, setRemoveGroups] = useState(true); const [removeLicenses, setRemoveLicenses] = useState(true); const [autoReplies, setAutoReplies] = useState(true); const [finishedPassword, setFinishedPassword] = useState("");
  const galLoading = actionKey === "global_address_list" && dataLoading;
  const finalPassword = passwordMode === "auto" ? (password || "Tt-" + crypto.randomUUID().replaceAll("-", "").slice(0, 16) + "!a9") : password;
  const category = actionKey === "m365_groups" ? "m365" : actionKey === "security_groups" ? "security" : actionKey === "distribution_groups" ? "distribution" : "";
  const filteredGroups = useMemo(() => groups.filter((group) => `${group.display_name} ${group.mail || ""}`.toLowerCase().includes(groupSearch.toLowerCase())), [groups, groupSearch]);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      const needsGroups = ["m365_groups", "security_groups", "distribution_groups"].includes(actionKey);
      const needsLicenses = actionKey === "licenses" || actionKey === "offboard";
      const needsMailboxes = actionKey === "shared_mailboxes";
      const needsReplies = actionKey === "out_of_office";
      const needsGal = actionKey === "global_address_list";
      if (!needsGroups && !needsLicenses && !needsMailboxes && !needsReplies && !needsGal) return;
      setDataLoading(true); setDataError("");
      try {
        const tasks: Promise<void>[] = [];
        if (needsGroups) tasks.push(request<Group[]>(`/api/users/groups?tenant_id=${encodeURIComponent(user.tenant_id)}&user_id=${encodeURIComponent(user.user_id)}&category=${category}`, token).then((value) => { if (!cancelled) setGroups(value); }));
        if (needsLicenses) {
          tasks.push(request<{ licenses: License[] }>(`/api/users/licenses?tenant_id=${encodeURIComponent(user.tenant_id)}&user_id=${encodeURIComponent(user.user_id)}`, token).then((value) => { if (!cancelled) setLicenses(value.licenses || []); }));
          tasks.push(request<License[]>(`/api/tenants/${encodeURIComponent(user.tenant_id)}/licenses`, token).then((value) => { if (!cancelled) setAvailableLicenses(value); }));
        }
        if (needsMailboxes) tasks.push(request<{ mailboxes?: Mailbox[] }>(`/api/users/shared-mailboxes?tenant_id=${encodeURIComponent(user.tenant_id)}&user_id=${encodeURIComponent(user.user_id)}`, token).then((value) => { if (!cancelled) { setMailboxes(value.mailboxes || []); setSelectedMailbox(""); } }));
        if (needsReplies) tasks.push(request<{ automatic_replies_setting?: AutomaticReplies }>(`/api/users/automatic-replies?tenant_id=${encodeURIComponent(user.tenant_id)}&user_id=${encodeURIComponent(user.user_id)}`, token).then((value) => { const reply = value.automatic_replies_setting || {}; if (!cancelled) { setReplyStatus(reply.status || "disabled"); setInternalReply(reply.internalReplyMessage || ""); setExternalReply(reply.externalReplyMessage || ""); setReplyStart(reply.scheduledStartDateTime ? reply.scheduledStartDateTime.slice(0, 16) : ""); setReplyEnd(reply.scheduledEndDateTime ? reply.scheduledEndDateTime.slice(0, 16) : ""); } }));
        if (needsGal) tasks.push(request<{ hidden?: boolean }>(`/api/users/global-address-list?tenant_id=${encodeURIComponent(user.tenant_id)}&user_id=${encodeURIComponent(user.user_id)}`, token).then((value) => { if (!cancelled && typeof value.hidden === "boolean") setHideGal(value.hidden); }));
        await Promise.all(tasks);
      } catch (error) { if (!cancelled) setDataError(error instanceof Error ? error.message : "Action data could not be loaded."); } finally { if (!cancelled) setDataLoading(false); }
    };
    void load(); return () => { cancelled = true; };
  }, [actionKey, category, token, user.tenant_id, user.user_id]);

  const actionData = () => {
    if (actionKey === "reset_password") return { force_change: forceChange, revoke_sessions: revoke };
    if (actionKey === "block") return { revoke_sessions: revoke, reason: reason.trim() };
    if (actionKey === "create_tap") return { lifetime_minutes: Number(tapLifetime), usable_once: true };
    if (actionKey === "out_of_office") return { automatic_replies_setting: { status: replyStatus, internalReplyMessage: internalReply, externalReplyMessage: externalReply, ...(replyStatus === "scheduled" ? { scheduledStartDateTime: new Date(replyStart).toISOString(), scheduledEndDateTime: new Date(replyEnd).toISOString() } : {}) } };
    if (actionKey === "global_address_list") return { hidden: hideGal };
    if (actionKey === "email_forwarding") return { recipient: forwarding ? recipient.trim() : null, keep_copy: keepCopy };

    if (actionKey === "licenses") return { add_licenses: availableLicenses.filter((item) => selectedLicenseIds.includes(item.sku_id) && !licenses.some((current) => current.sku_id === item.sku_id)).map((item) => ({ skuId: item.sku_id })), remove_sku_ids: licenses.filter((item) => !selectedLicenseIds.includes(item.sku_id)).map((item) => item.sku_id) };
    if (actionKey === "shared_mailboxes") return { permissions: [{ mailbox: selectedMailbox, full_access: fullAccess, send_as: sendAs, send_on_behalf: sendOnBehalf, auto_mapping: autoMapping }] };
    return {};
  };

  const [groupSelection, setGroupSelection] = useState<string[]>([]); const [selectedLicenseIds, setSelectedLicenseIds] = useState<string[]>([]);
  useEffect(() => { setGroupSelection(groups.filter((item) => item.is_member).map((item) => item.id)); }, [groups]);
  useEffect(() => { setSelectedLicenseIds(licenses.map((item) => item.sku_id)); }, [licenses]);
  const actualActionData = () => {
    if (["m365_groups", "security_groups", "distribution_groups"].includes(actionKey)) return { add_group_ids: groupSelection.filter((id) => !groups.find((item) => item.id === id)?.is_member), remove_group_ids: groups.filter((item) => item.is_member && !groupSelection.includes(item.id)).map((item) => item.id) };
    return actionData();
  };
  const postAction = (action: string, data: Record<string, unknown> = {}, actionPassword?: string) => request<{ remaining?: string[] }>("/api/users/action", token, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ tenant_id: user.tenant_id, user_id: user.user_id, action, password: actionPassword, action_data: data, confirm: true }) });
  const run = async () => {
    if (!isFinish) { setStep(step + 1); return; }
    if (dataLoading) return;
    if (actionKey === "block" && !reason.trim()) { onMessage("A reason is required before blocking sign-in."); return; }
    if (actionKey === "reset_password" && finalPassword.length < 12) { onMessage("The password must be at least 12 characters."); return; }
    if (actionKey === "out_of_office" && replyStatus === "scheduled" && (!replyStart || !replyEnd || new Date(replyStart) >= new Date(replyEnd))) { onMessage("Enter a valid automatic-reply schedule."); return; }
    if (actionKey === "shared_mailboxes" && (!selectedMailbox || !(fullAccess || sendAs || sendOnBehalf))) { onMessage("Select a shared mailbox and at least one permission."); return; }
    setBusy(true);
    try {
      if (actionKey === "offboard") {
        if (offboardSessions) await postAction("revoke_sessions");
        if (disableAccount) await postAction("block", { reason: "Offboarding" });
        if (removeGroups) for (const groupCategory of ["m365_groups", "security_groups", "distribution_groups"]) { const loaded = await request<Group[]>(`/api/users/groups?tenant_id=${encodeURIComponent(user.tenant_id)}&user_id=${encodeURIComponent(user.user_id)}&category=${groupCategory}`, token); const ids = loaded.filter((item) => item.is_member).map((item) => item.id); if (ids.length) await postAction(groupCategory, { remove_group_ids: ids, add_group_ids: [] }); }
        if (removeLicenses && licenses.length) await postAction("licenses", { add_licenses: [], remove_sku_ids: licenses.map((item) => item.sku_id) });
        if (convertMailbox) await postAction("convert_mailbox");
        if (autoReplies) await postAction("out_of_office", { automatic_replies_setting: { status: "enabled", internalReplyMessage: "", externalReplyMessage: "" } });
      } else {
        const apiAction = actionKey === "block" ? (user.account_enabled && blockSignIn ? "block" : "unblock") : actionKey;
        await postAction(apiAction, actualActionData(), actionKey === "reset_password" ? finalPassword : undefined);
        if (actionKey === "reset_password" && passwordMode === "auto") setFinishedPassword(finalPassword);
      }
      onMessage(`${title} completed.`); onClose();
    } catch (error) { onMessage(error instanceof Error ? error.message : "Action failed"); } finally { setBusy(false); }
  };
  const isFinish = step === actionSteps.length - 1;
  const summary = actionKey === "out_of_office" ? [`Automatic replies: ${replyStatus}`, "Internal and external messages configured"] : actionKey === "shared_mailboxes" ? [`Mailbox: ${mailboxes.find((item) => [item.id, item.alias, item.primary_smtp_address].includes(selectedMailbox))?.display_name || selectedMailbox || "Not selected"}`, `Permissions: ${[fullAccess && "Full Access", sendAs && "Send As", sendOnBehalf && "Send on Behalf"].filter(Boolean).join(", ") || "None"}`] : actionKey === "licenses" ? [`Add ${Math.max(0, selectedLicenseIds.filter((id) => !licenses.some((item) => item.sku_id === id)).length)} license(s)`, `Remove ${licenses.filter((item) => !selectedLicenseIds.includes(item.sku_id)).length} license(s)`] : actionKey === "offboard" ? [`Convert mailbox: ${convertMailbox ? "Yes" : "No"}`, `Disable sign-in: ${disableAccount ? "Yes" : "No"}`, `Revoke sessions: ${offboardSessions ? "Yes" : "No"}`, `Remove groups: ${removeGroups ? "Yes" : "No"}`, `Remove licenses: ${removeLicenses ? "Yes" : "No"}`] : ["Review the selected Microsoft 365 changes", "The final diff will be recorded in the audit log"];

  const configure = <>{actionKey === "reset_password" && <><h3>Password</h3><Choice label="Auto-generate secure password" checked={passwordMode === "auto"} onChange={() => setPasswordMode("auto")} /><Choice label="Set custom password" checked={passwordMode === "custom"} onChange={() => setPasswordMode("custom")} />{passwordMode === "custom" && <label className="form-field"><span>New password</span><input type="password" minLength={12} value={password} onChange={(event) => setPassword(event.target.value)} /></label>}</>}{actionKey === "block" && <><Toggle label="Block sign-in" checked={blockSignIn} onChange={setBlockSignIn} /><label className="form-field"><span>Reason (required)</span><textarea rows={3} value={reason} onChange={(event) => setReason(event.target.value)} /></label><Toggle label="Also revoke active sessions immediately" checked={revoke} onChange={setRevoke} /></>}{actionKey === "out_of_office" && <><h3>Automatic replies</h3><Choice label="Disabled" checked={replyStatus === "disabled"} onChange={() => setReplyStatus("disabled")} /><Choice label="Enabled" checked={replyStatus === "enabled"} onChange={() => setReplyStatus("enabled")} /><Choice label="Scheduled" checked={replyStatus === "scheduled"} onChange={() => setReplyStatus("scheduled")} />{replyStatus === "scheduled" && <div className="form-grid"><label className="form-field"><span>Start</span><input type="datetime-local" value={replyStart} onChange={(event) => setReplyStart(event.target.value)} /></label><label className="form-field"><span>End</span><input type="datetime-local" value={replyEnd} onChange={(event) => setReplyEnd(event.target.value)} /></label></div>}</>}{actionKey === "global_address_list" && <Toggle label="Hide from Global Address List" checked={hideGal} disabled={galLoading} onChange={setHideGal} />}{actionKey === "email_forwarding" && <><Toggle label="Enable forwarding" checked={forwarding} onChange={setForwarding} />{forwarding && <label className="form-field"><span>Forward emails to</span><input type="email" value={recipient} onChange={(event) => setRecipient(event.target.value)} /></label>}</>}{["m365_groups", "security_groups", "distribution_groups"].includes(actionKey) && <><p>{groups.length} groups loaded. Select memberships to keep.</p>{groups.length ? <><input className="form-field" aria-label="Search available groups" value={groupSearch} onChange={(event) => setGroupSearch(event.target.value)} />{filteredGroups.map((group) => <Check key={group.id} label={`${group.display_name}${group.mail ? ` (${group.mail})` : ""}`} checked={groupSelection.includes(group.id)} onChange={(checked) => setGroupSelection(checked ? [...groupSelection, group.id] : groupSelection.filter((id) => id !== group.id))} />)}</> : <div className="action-notice">No groups were returned.</div>}</>}{actionKey === "licenses" && <>{availableLicenses.length ? availableLicenses.map((license) => <Check key={license.sku_id} label={license.display_name || license.sku_part_number || license.sku_id} checked={selectedLicenseIds.includes(license.sku_id)} onChange={(checked) => setSelectedLicenseIds(checked ? [...selectedLicenseIds, license.sku_id] : selectedLicenseIds.filter((id) => id !== license.sku_id))} />) : <div className="action-notice">No tenant license catalog is available.</div>}</>}{actionKey === "shared_mailboxes" && <>{mailboxes.length ? <><label className="form-field"><span>Shared mailbox</span><select value={selectedMailbox} onChange={(event) => setSelectedMailbox(event.target.value)}><option value="">Select a shared mailbox</option>{mailboxes.map((mailbox) => { const identity = mailbox.primary_smtp_address || mailbox.alias || mailbox.id || ""; return <option value={identity} key={identity}>{mailbox.display_name || identity}</option>; })}</select></label></> : <div className="action-notice">No shared mailboxes were returned.</div>}</>}{actionKey === "offboard" && <><p>Only the selected steps will be run for {user.display_name}.</p><Toggle label="Convert to shared mailbox" checked={convertMailbox} onChange={setConvertMailbox} /><Toggle label="Disable sign-in" checked={disableAccount} onChange={setDisableAccount} /><Toggle label="Revoke all active sessions" checked={offboardSessions} onChange={setOffboardSessions} /><Toggle label="Remove all group memberships" checked={removeGroups} onChange={setRemoveGroups} /><Toggle label="Remove all licenses" checked={removeLicenses} onChange={setRemoveLicenses} /><Toggle label="Enable automatic replies" checked={autoReplies} onChange={setAutoReplies} /></>}</>;
  const options = <>{actionKey === "reset_password" && <><Toggle label="Require password change at next sign-in" checked={forceChange} onChange={setForceChange} /><Toggle label="Revoke all active sessions after reset" checked={revoke} onChange={setRevoke} /></>}{actionKey === "out_of_office" && <><label className="form-field"><span>Internal reply message</span><textarea rows={4} value={internalReply} onChange={(event) => setInternalReply(event.target.value)} /></label><label className="form-field"><span>External reply message</span><textarea rows={4} value={externalReply} onChange={(event) => setExternalReply(event.target.value)} /></label></>}{actionKey === "shared_mailboxes" && <><Check label="Full Access" checked={fullAccess} onChange={setFullAccess} /><Check label="Send As" checked={sendAs} onChange={setSendAs} /><Check label="Send on Behalf" checked={sendOnBehalf} onChange={setSendOnBehalf} /><Toggle label="Auto-map in Outlook" checked={autoMapping} onChange={setAutoMapping} /></>}{actionKey === "create_tap" && <label className="form-field"><span>Lifetime (minutes)</span><select value={tapLifetime} onChange={(event) => setTapLifetime(event.target.value)}><option>30</option><option>60</option><option>120</option><option>480</option></select></label>}</>;
  return <><div className="drawer-backdrop" onClick={onClose} /><aside className="user-action-drawer" role="dialog" aria-modal="true" aria-labelledby="user-action-title"><button className="drawer-close" type="button" aria-label="Close action panel" onClick={onClose}>×</button><div className="drawer-heading"><div className="drawer-eyebrow">USER MANAGEMENT</div><h2 id="user-action-title">{title}</h2><div className="sub">{user.display_name}</div><div className="sub">{user.user_principal_name}</div></div><div className="drawer-progress">{actionSteps.map((item, index) => <button type="button" className={index === step ? "active" : index < step ? "complete" : ""} disabled={index > step} key={item} onClick={() => setStep(index)}>{index + 1}. {item}</button>)}</div><div className="drawer-content">{dataError && <div className="drawer-note">Could not load current data: {dataError}</div>}{dataLoading && <div className="action-notice">Loading current tenant data…</div>}{isFinish ? <><h3>Review and confirm</h3><p>Verify the selected changes for this user. The final action will be recorded in the audit log.</p><Summary items={summary} />{finishedPassword && <div className="revealed-secret"><strong>One-time password</strong><code>{finishedPassword}</code><span>This will not be shown again after closing this panel.</span></div>}</> : <>{step === 0 ? configure : options}</>}</div><div className="drawer-footer"><button className="btn" type="button" onClick={() => step === 0 ? onClose() : setStep(step - 1)}>{step === 0 ? "Cancel" : "Back"}</button><button className={`btn ${actionKey === "offboard" && isFinish ? "btn-danger" : "btn-primary"}`} type="button" disabled={busy || dataLoading} onClick={run}>{busy ? "Running…" : isFinish ? "Continue & Run" : "Next"}</button></div></aside></>;
}
